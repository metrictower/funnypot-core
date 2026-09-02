<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\SchemaVersion;
use Funnypot\Core\Store\PhpArrayStore;
use PharData;
use Throwable;

/**
 * Fetches a signed rules release and hot-swaps it into a data dir the engine prefers over its
 * bundled artifacts — no `composer update`. Trust flow, in order, ALL before anything goes live:
 *
 *   fetch (allow-listed HTTPS) -> ed25519 verify the manifest -> sha256 the tarball against the
 *   signed manifest -> extract to an unreferenced .partial dir -> per-file sha256 -> prove every
 *   .php is a pure literal (PhpLiteralValidator) -> fetch-time safety subset (fingerprint-denylist
 *   re-scan + ReDoS budget on every regex + anti-blinding coverage floor) -> atomic symlink swap
 *   -> opcache invalidate + drop the in-process store cache.
 *
 * Fail-safe is STRUCTURAL, not a convention: every failure path returns before the swap, so
 * `current` is untouched and RulesLocator keeps serving the prior release, or the bundled floor.
 * There is no code path that blanks the rules. A non-blocking flock serialises concurrent runs;
 * a monotonic version_seq refuses a downgrade unless rollback() is the explicit caller.
 */
final class RulesUpdater
{
    /** The compiled artifacts funnypot-core reads; each MUST be present and pass validation. */
    private const ENGINE_ARTIFACTS = [
        'nuclei-index.full.php',
        'funnypot-attack.php',
        'funnypot-routes.php',
        'funnypot-routes-index.php',
        'funnypot-param.php',
    ];

    /** Upper bound on the DECOMPRESSED release (the .tar inside the .gz): a signed gzip bomb must not
     *  be able to fill the disk. The real release is ~6 MB; this is a generous floor. */
    private const MAX_EXTRACTED_BYTES = 128 * 1024 * 1024;

    /** Upper bound on file count in a release (an inode-exhaustion / second gzip-bomb floor). */
    private const MAX_ENTRIES = 8000;

    /** Clock-skew tolerance for signed freshness windows (seconds). Conventional; do not widen past
     *  half the shortest TTL or a freeze attack regains a window. */
    private const SKEW = 300;

    /** @var int|null Test seam: freezes the wall clock so freshness/key-window checks are deterministic. */
    private $nowOverride = null;

    /** @var int|null Test seam: shrinks the decompression cap so the gzip-bomb test stays fast. */
    private $maxExtractedBytesOverride = null;

    /** @var string */
    private $dataDir;

    /** @var string */
    private $channel;

    /** @var string|null */
    private $pinnedVersion;

    /** @var string */
    private $repoBaseUrl;

    /** @var int */
    private $retention;

    /** @var float */
    private $coverageFloorRatio;

    /** @var HttpFetcher */
    private $fetcher;

    /** @var SignatureVerifier */
    private $verifier;

    /** @var PhpLiteralValidator */
    private $validator;

    /** @var ReDosGuard */
    private $redos;

    /** @var FingerprintGuard */
    private $fingerprint;

    /** @var array|null Test seam: overrides the first-install coverage baseline so tests need no 6 MB fixture. */
    private $packagedCoverageOverride = null;

    public function __construct(
        string $dataDir,
        string $channel = 'stable',
        ?string $pinnedVersion = null,
        string $repoBaseUrl = 'https://github.com/metrictower/funnypot-rules',
        ?HttpFetcher $fetcher = null,
        ?SignatureVerifier $verifier = null,
        ?PhpLiteralValidator $validator = null,
        ?ReDosGuard $redos = null,
        ?FingerprintGuard $fingerprint = null,
        int $retention = 3,
        float $coverageFloorRatio = 0.5
    ) {
        $this->dataDir = rtrim($dataDir, '/');
        $this->channel = $channel;
        $this->pinnedVersion = $pinnedVersion !== null && $pinnedVersion !== '' ? $pinnedVersion : null;
        $this->repoBaseUrl = rtrim($repoBaseUrl, '/');
        $this->retention = max(1, $retention);
        $this->coverageFloorRatio = $coverageFloorRatio;
        $this->fetcher = $fetcher ?? new CurlFetcher();
        $this->verifier = $verifier ?? SignatureVerifier::fromPackage();
        $this->validator = $validator ?? new PhpLiteralValidator();
        $this->redos = $redos ?? new ReDosGuard();
        $this->fingerprint = $fingerprint ?? FingerprintGuard::fromPackage();
    }

    /** Test-only: pin the baseline used on a first install (avoids reading the packaged floor). */
    public function setPackagedCoverageForTesting(array $coverage): void
    {
        $this->packagedCoverageOverride = $coverage;
    }

    /** Test-only: freeze the wall clock (unix seconds) so freshness + key-window checks are deterministic. */
    public function setNowForTesting(int $now): void
    {
        $this->nowOverride = $now;
    }

    /** Test-only: shrink the decompression cap so a gzip-bomb fixture need not be 128 MiB. */
    public function setMaxExtractedBytesForTesting(int $bytes): void
    {
        $this->maxExtractedBytesOverride = max(1, $bytes);
    }

    /** The single wall clock the whole update shares (freshness windows, key windows, stamps). */
    private function now(): int
    {
        return $this->nowOverride ?? time();
    }

    /** RFC3339/`gmdate('c')` stamp at the shared clock (deterministic under the test seam). */
    private function nowStamp(): string
    {
        return gmdate('c', $this->now());
    }

    private function maxExtractedBytes(): int
    {
        return $this->maxExtractedBytesOverride ?? self::MAX_EXTRACTED_BYTES;
    }

    // ---------------------------------------------------------------- update()

    public function update(): UpdateResult
    {
        $state = $this->readState();
        $currentVersion = $state['version'] ?? null;

        $lock = $this->acquireLock();
        if ($lock === null) {
            // A concurrent run holds the lock; treat as a benign no-op rather than contend.
            return new UpdateResult(true, false, 'busy', $currentVersion, $currentVersion, 'Another update is in progress.');
        }

        $partial = null;
        try {
            $this->ensureDir($this->dataDir);
            $this->ensureDir($this->dataDir . '/releases');

            // 1. Resolve the target version (explicit pin, else the signed channels pointer). A
            //    channels pointer is verified for freshness here (resolveChannelVersion throws
            //    stale-metadata on a replayed/expired pointer) — so reaching step 3 already proves a
            //    FRESH signed pointer, which is what lets touchChecked() advance checked_at safely.
            //    A PINNED install skips channels entirely and thus BYPASSES the revoked list — its
            //    freshness anchor is the manifest's own 90-day window (enforced in step 2), so a
            //    pinned host can lag revocation by at most that TTL. (The future offline --from=file
            //    path is the deliberate escape hatch; a >90-day-old pinned release now fails closed.)
            $channelGeneratedAt = null;
            if ($this->pinnedVersion !== null) {
                $target = $this->pinnedVersion;
            } else {
                [$target, $channelGeneratedAt] = $this->resolveChannelVersion();
            }

            // 2. Fetch + verify the manifest (the signed root); its own freshness window is enforced.
            [$manifest, $keyId] = $this->fetchVerifiedManifest($target);
            $version = (string) $manifest['version'];
            $seq = (int) $manifest['version_seq'];

            // 3. No-op if already current — before any tarball download. checked_at means "verified a
            //    fresh signed pointer" (channel mode) or "verified a fresh signed manifest" (pinned
            //    mode); either way a freeze/replay of stale metadata threw above and never reaches here.
            if ($currentVersion === $version) {
                $this->touchChecked($state, $channelGeneratedAt);

                return UpdateResult::noop($currentVersion);
            }

            // 4. Anti-downgrade: a plain update() must never move to an older sequence.
            if (isset($state['version_seq']) && $seq <= (int) $state['version_seq']) {
                throw new RulesUpdateException(
                    RulesUpdateException::REASON_DOWNGRADE,
                    "Refusing to move from seq {$state['version_seq']} to older/equal seq {$seq} (use rollback)."
                );
            }

            // 5. Fetch the tarball; its bytes must match the signed sha256.
            $tarball = $this->fetcher->get($this->assetUrl($target, (string) $manifest['tarball']));
            if (hash('sha256', $tarball) !== strtolower((string) $manifest['tarball_sha256'])) {
                throw new RulesUpdateException(RulesUpdateException::REASON_SHA_MISMATCH, 'Tarball sha256 does not match the signed manifest.');
            }

            // 6. Extract into an unreferenced .partial dir on the same filesystem.
            $partial = $this->dataDir . '/.partial-' . getmypid() . '-' . bin2hex(random_bytes(4));
            $this->extractTarball($tarball, $partial);
            unset($tarball);

            // 7. Per-file sha256 against the manifest; every listed file present, none missing.
            $this->verifyFileHashes($partial, (array) $manifest['files']);

            // 8. The manifest is the COMPLETE allowlist. Walk the extracted tree: reject any symlink
            //    and any file the manifest does not list, then prove EVERY .php physically on disk is
            //    a pure literal before it can ever be require'd. Validating the ON-DISK set (not just
            //    the listed set) is what closes the unlisted-file RCE: an attacker-authored manifest
            //    can omit a malicious .php from `files`, but it cannot keep it off disk, and
            //    runSafetySubset() below require()s the engine artifacts.
            $engineDir = $partial . '/engine';
            $listed = (array) $manifest['files'];
            foreach ($this->listTreeFiles($partial) as $rel) {
                if (!isset($listed[$rel])) {
                    throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "Unlisted file in release: {$rel}.");
                }
                if (substr($rel, -4) === '.php') {
                    try {
                        $this->validator->validateFile($partial . '/' . $rel, $rel);
                    } catch (PhpLiteralViolation $e) {
                        throw new RulesUpdateException(RulesUpdateException::REASON_NOT_LITERAL, $e->getMessage());
                    }
                }
            }
            foreach (self::ENGINE_ARTIFACTS as $artifact) {
                if (!is_file($engineDir . '/' . $artifact)) {
                    throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "Release is missing engine artifact {$artifact}.");
                }
            }

            // 9. Fetch-time safety subset (source-free defence-in-depth against a bad signer).
            $this->runSafetySubset($engineDir, $state);

            // 10. Atomic activation + cache-bust. Nothing above this line touched `current`.
            $releaseDir = $this->dataDir . '/releases/' . $this->safeVersionDir($version);
            $this->promotePartial($partial, $releaseDir);
            $partial = null;
            $coverage = $this->computeCoverage($releaseDir . '/engine');
            $this->writeReleaseMeta($releaseDir, $version, $seq, $keyId, $coverage);
            $this->activate($releaseDir . '/engine');

            // 11. Record the new pin, prune old releases, done.
            $this->writeState([
                'version' => $version,
                'version_seq' => $seq,
                'key_id' => $keyId,
                'applied_at' => $this->nowStamp(),
                'checked_at' => $this->nowStamp(),
                'channel_generated_at' => $channelGeneratedAt ?? ($state['channel_generated_at'] ?? null),
                'coverage' => $coverage,
            ]);
            $this->prune($releaseDir);

            return UpdateResult::updated($currentVersion, $version);
        } catch (RulesUpdateException $e) {
            if ($partial !== null) {
                $this->rmrf($partial);
            }

            return UpdateResult::failed($e->reason(), $e->getMessage(), $currentVersion);
        } catch (Throwable $e) {
            if ($partial !== null) {
                $this->rmrf($partial);
            }

            return UpdateResult::failed('error', $e->getMessage(), $currentVersion);
        } finally {
            $this->releaseLock($lock);
        }
    }

    // -------------------------------------------------------------- rollback()

    /**
     * Re-point `current` at a retained prior release — local, network-free, instant. The target
     * was fully verified when it was installed and lives in the updater-owned dir; rollback
     * re-points it without re-fetching. With no $toVersion, rolls back to the newest retained
     * release other than the one currently live.
     */
    public function rollback(?string $toVersion = null): UpdateResult
    {
        $state = $this->readState();
        $current = $state['version'] ?? null;

        $lock = $this->acquireLock();
        if ($lock === null) {
            return new UpdateResult(true, false, 'busy', $current, $current, 'Another update is in progress.');
        }

        try {
            $retained = $this->retainedVersions();
            if ($retained === []) {
                throw new RulesUpdateException(RulesUpdateException::REASON_NOT_RETAINED, 'No retained releases on disk to roll back to.');
            }

            if ($toVersion === null) {
                $candidates = array_values(array_filter($retained, function ($v) use ($current) {
                    return $v !== $current;
                }));
                if ($candidates === []) {
                    throw new RulesUpdateException(RulesUpdateException::REASON_NOT_RETAINED, 'No retained release other than the current one.');
                }
                $toVersion = $candidates[0];
            }

            $releaseDir = $this->dataDir . '/releases/' . $this->safeVersionDir($toVersion);
            if (!is_dir($releaseDir . '/engine')) {
                throw new RulesUpdateException(RulesUpdateException::REASON_NOT_RETAINED, "Version {$toVersion} is not retained locally.");
            }

            $meta = $this->readJsonFile($releaseDir . '/meta.json') ?? ['version' => $toVersion, 'version_seq' => 0, 'coverage' => []];
            $this->activate($releaseDir . '/engine');
            $this->writeState([
                'version' => (string) ($meta['version'] ?? $toVersion),
                'version_seq' => (int) ($meta['version_seq'] ?? 0),
                'key_id' => $meta['key_id'] ?? null,
                'applied_at' => $this->nowStamp(),
                'checked_at' => $state['checked_at'] ?? $this->nowStamp(),
                'channel_generated_at' => $state['channel_generated_at'] ?? null,
                'coverage' => (array) ($meta['coverage'] ?? []),
            ]);

            return UpdateResult::rolledBack($current, (string) ($meta['version'] ?? $toVersion));
        } catch (RulesUpdateException $e) {
            return UpdateResult::failed($e->reason(), $e->getMessage(), $current);
        } catch (Throwable $e) {
            return UpdateResult::failed('error', $e->getMessage(), $current);
        } finally {
            $this->releaseLock($lock);
        }
    }

    // ---------------------------------------------------------------- status()

    public function status(): RulesStatus
    {
        $state = $this->readState();
        $live = is_link($this->dataDir . '/current') || is_dir($this->dataDir . '/current');

        return new RulesStatus(
            $live && ($state['version'] ?? null) !== null ? 'data-dir' : 'bundled',
            $state['version'] ?? null,
            isset($state['version_seq']) ? (int) $state['version_seq'] : null,
            $state['applied_at'] ?? null,
            $state['checked_at'] ?? null,
            (array) ($state['coverage'] ?? []),
            $this->retainedVersions(),
            $state['channel_generated_at'] ?? null
        );
    }

    // ----------------------------------------------------------- verify flow

    /**
     * @return array{0:array<string,mixed>,1:string} [manifest, verifying key_id]
     */
    private function fetchVerifiedManifest(string $version): array
    {
        $manifestBytes = $this->fetcher->get($this->assetUrl($version, $version . '.manifest.json'));
        $sig = $this->fetcher->get($this->assetUrl($version, $version . '.manifest.json.sig'));

        // The manifest signature is over CONTEXT_MANIFEST . bytes, and only a `release`-role key may
        // verify it — a channels-key signature (pointer mover) can never authenticate a release.
        $keyId = $this->verifier->verify(
            $manifestBytes,
            $this->normaliseSignature($sig),
            SignatureVerifier::CONTEXT_MANIFEST,
            SignatureVerifier::ROLE_RELEASE,
            $this->now()
        );

        $manifest = json_decode($manifestBytes, true);
        if (!is_array($manifest)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest is not valid JSON.');
        }
        foreach (['schema', 'version', 'version_seq', 'tarball', 'tarball_sha256', 'files'] as $field) {
            if (!isset($manifest[$field])) {
                throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "Manifest is missing '{$field}'.");
            }
        }
        $schema = (int) $manifest['schema'];
        // Fail-safe forward-compat: a schema ahead of the update-channel envelope this engine
        // understands means the release format changed, and an older engine must refuse it rather
        // than mis-parse it. This is the ENVELOPE schema (RELEASE_CURRENT), not the template DSL.
        if ($schema > SchemaVersion::RELEASE_CURRENT) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_SCHEMA_TOO_NEW,
                "Release schema {$schema} exceeds the engine's supported schema " . SchemaVersion::RELEASE_CURRENT . " — refusing to load (upgrade funnypot-core)."
            );
        }
        if ($schema < 1) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Unsupported manifest schema.');
        }
        // The manifest's own version must match the tag we asked for (no bait-and-switch).
        if ((string) $manifest['version'] !== $version) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest version does not match the requested tag.');
        }
        // Signed freshness (schema >= 2): a replayed old-but-validly-signed manifest is rejected as
        // stale so a pin (or a fresh install) cannot be pointed at a long-dead release.
        if ($schema >= 2) {
            $this->assertFresh($manifest, 'manifest', $this->now());
        }

        return [$manifest, $keyId];
    }

    /**
     * @return array{0:string,1:?string} [target version, the pointer's signed generated_at]
     */
    private function resolveChannelVersion(): array
    {
        $bytes = $this->fetcher->get($this->assetUrl('channels', 'channels.json'));
        $sig = $this->fetcher->get($this->assetUrl('channels', 'channels.json.sig'));
        // The channels signature is over CONTEXT_CHANNELS . bytes, and only a `channels`-role key may
        // verify it — a release-key signature can never move the pointer.
        $this->verifier->verify(
            $bytes,
            $this->normaliseSignature($sig),
            SignatureVerifier::CONTEXT_CHANNELS,
            SignatureVerifier::ROLE_CHANNELS,
            $this->now()
        );

        $channels = json_decode($bytes, true);
        if (!is_array($channels)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'channels.json is not valid JSON.');
        }
        // The channels envelope carries a schema too (it was unchecked before schema 2). Same
        // fail-safe forward-compat gate as the manifest: refuse a pointer format we can't parse.
        if (!isset($channels['schema'])) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "channels.json is missing 'schema'.");
        }
        $schema = (int) $channels['schema'];
        if ($schema > SchemaVersion::RELEASE_CURRENT) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_SCHEMA_TOO_NEW,
                "Channels schema {$schema} exceeds the engine's supported schema " . SchemaVersion::RELEASE_CURRENT . " — refusing to load (upgrade funnypot-core)."
            );
        }
        if ($schema < 1) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Unsupported channels schema.');
        }
        // Signed freshness (schema >= 2): a replayed/frozen pointer is rejected as stale BEFORE it is
        // trusted — this is what kills the freeze/replay attack that defeated revocation and silenced
        // the staleness alarm. Reaching past this point means the pointer is a fresh signed document.
        if ($schema >= 2) {
            $this->assertFresh($channels, 'channels.json', $this->now());
        }

        $version = (string) ($channels[$this->channel] ?? '');
        if ($version === '') {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "Channel '{$this->channel}' is not defined in channels.json.");
        }
        if (in_array($version, (array) ($channels['revoked'] ?? []), true)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_DOWNGRADE, "Version {$version} is revoked.");
        }

        $generatedAt = isset($channels['generated_at']) ? (string) $channels['generated_at'] : null;

        return [$version, $generatedAt];
    }

    /**
     * Reject a signed document whose freshness window is missing, unparseable, expired, or
     * implausibly future. Fail-closed: any doubt about the metadata's age drops the update (the
     * caller degrades to last-good), it never applies stale/forged metadata. Timestamps are parsed
     * strictly (RFC3339), NOT via lenient strtotime, mirroring KeyRing's fail-closed date rule.
     *
     * @param array<string,mixed> $doc
     */
    private function assertFresh(array $doc, string $what, int $now): void
    {
        $generatedAt = isset($doc['generated_at']) ? $this->parseTimestamp((string) $doc['generated_at']) : null;
        $expires = isset($doc['expires']) ? $this->parseTimestamp((string) $doc['expires']) : null;
        if ($generatedAt === null || $expires === null) {
            // Freshness is not optional once the format carries it (schema >= 2): a missing or
            // unparseable window is treated as a broken/forged envelope, not "assume fresh".
            throw new RulesUpdateException(
                RulesUpdateException::REASON_BAD_MANIFEST,
                "The {$what} is missing a parseable generated_at/expires freshness window."
            );
        }
        if ($now > $expires + self::SKEW) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_STALE_METADATA,
                "The {$what} expired (expires=" . gmdate('c', $expires) . ', now=' . gmdate('c', $now) . ') — refusing stale signed metadata (serving last-good).'
            );
        }
        if ($generatedAt > $now + self::SKEW) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_STALE_METADATA,
                "The {$what} is dated in the future (generated_at=" . gmdate('c', $generatedAt) . ', now=' . gmdate('c', $now) . ') — broken publisher clock or clock-skew attack.'
            );
        }
    }

    /**
     * Strict RFC3339 timestamp parse for a freshness field. Returns null on anything unparseable so
     * assertFresh can fail closed.
     */
    private function parseTimestamp(string $value): ?int
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        $utc = new DateTimeZone('UTC');
        foreach ([DateTimeInterface::RFC3339, 'Y-m-d\TH:i:s\Z', '!Y-m-d'] as $format) {
            $dt = DateTimeImmutable::createFromFormat($format, $value, $utc);
            $errors = DateTimeImmutable::getLastErrors();
            $clean = $errors === false || (($errors['warning_count'] ?? 0) === 0 && ($errors['error_count'] ?? 0) === 0);
            if ($dt !== false && $clean) {
                return $dt->getTimestamp();
            }
        }

        return null;
    }

    /** Accept a raw 64-byte signature or a base64/hex-encoded one. */
    private function normaliseSignature(string $sig): string
    {
        // Raw binary first, and NEVER trim it: an ed25519 signature routinely starts or ends
        // with a byte whose value is whitespace, and trimming would corrupt it.
        if (strlen($sig) === SODIUM_CRYPTO_SIGN_BYTES) {
            return $sig;
        }

        $t = trim($sig);
        if (strlen($t) === SODIUM_CRYPTO_SIGN_BYTES) {
            return $t;
        }
        $b64 = base64_decode($t, true);
        if ($b64 !== false && strlen($b64) === SODIUM_CRYPTO_SIGN_BYTES) {
            return $b64;
        }
        if (strlen($t) === SODIUM_CRYPTO_SIGN_BYTES * 2 && ctype_xdigit($t)) {
            $bin = hex2bin($t);
            if ($bin !== false) {
                return $bin;
            }
        }

        return $sig; // let the verifier reject a wrong length
    }

    private function runSafetySubset(string $engineDir, array $state): void
    {
        $rules = require $engineDir . '/funnypot-attack.php';
        if (!is_array($rules)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Attack artifact did not return an array.');
        }

        // (a) fingerprint-denylist re-scan of every SERVED artifact: no upstream-detector signature
        //     may reach a response. The installed engine serves BOTH attack responses and route
        //     responses, so the route artifact is re-scanned too — same dual-shape + set_cookie +
        //     taunt extraction as the CI gate. Any hit is fail-closed: we throw before the swap.
        $this->rescanFingerprints($rules);
        $routes = require $engineDir . '/funnypot-routes.php';
        if (!is_array($routes)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Route artifact did not return an array.');
        }
        $this->rescanFingerprints($routes);

        // The param artifact is served content too, but bucketed (`buckets[<seg>][] = entry`);
        // flatten to its entries so the same rescan (each entry carries a `response`) covers it.
        $params = require $engineDir . '/funnypot-param.php';
        if (!is_array($params)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Param artifact did not return an array.');
        }
        $paramEntries = [];
        foreach ((array) ($params['buckets'] ?? []) as $entries) {
            foreach ((array) $entries as $entry) {
                $paramEntries[] = $entry;
            }
        }
        $this->rescanFingerprints($paramEntries);

        // (b) ReDoS budget on EVERY incoming regex, across every fetched artifact that can run PCRE
        //     on attacker bytes at runtime — not just an attack rule's top-level match. A poisoned
        //     signer can plant a catastrophic pattern in a param-bucket entry (matchParamRoute), a
        //     nested branch case `when.regex` (evalConditions), or a future shape; inspectArtifact
        //     walks each tree shape-agnostically so an un-screened regex cannot drift into coverage.
        //     funnypot-routes-index.php is NOT otherwise loaded here, so it is require'd explicitly
        //     (its .php was already proven a pure literal in step 8 before this runs).
        $this->redos->inspectArtifact($rules, 'funnypot-attack.php');
        $this->redos->inspectArtifact($routes, 'funnypot-routes.php');
        $this->redos->inspectArtifact($params, 'funnypot-param.php');
        $routesIndex = require $engineDir . '/funnypot-routes-index.php';
        if (!is_array($routesIndex)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Routes-index artifact did not return an array.');
        }
        $this->redos->inspectArtifact($routesIndex, 'funnypot-routes-index.php');

        // (c) anti-blinding floor: a fetched set that guts coverage is an attack, not an update.
        $new = $this->computeCoverage($engineDir);
        $baseline = isset($state['coverage']) && $state['coverage'] !== []
            ? (array) $state['coverage']
            : $this->packagedCoverage();
        foreach ($baseline as $metric => $was) {
            $was = (int) $was;
            if ($was <= 0) {
                continue;
            }
            $now = (int) ($new[$metric] ?? 0);
            if ($now < $was * $this->coverageFloorRatio) {
                throw new RulesUpdateException(
                    RulesUpdateException::REASON_BLINDING,
                    "Coverage floor: {$metric} dropped {$was} -> {$now} (below " . $this->coverageFloorRatio . ' of current).'
                );
            }
        }
    }

    /**
     * Fingerprint-denylist re-scan of one served-response artifact. Every served byte an attacker
     * can see must be covered, and there are two compiled shapes — attack rules nest served content
     * under `response`, route rules carry it at top level — so both are scanned. A hit throws,
     * rejecting the update before activation (invariant: a detector signature must never be served).
     *
     * @param array<int,mixed> $rules
     */
    private function rescanFingerprints(array $rules): void
    {
        foreach ($rules as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            $texts = array_merge(
                $this->servedTexts((array) ($rule['response'] ?? [])),
                $this->servedTexts($rule)
            );
            foreach ($texts as $text) {
                $hits = $this->fingerprint->scan($text);
                if ($hits !== []) {
                    throw new RulesUpdateException(
                        RulesUpdateException::REASON_FINGERPRINT_LEAK,
                        "Fingerprint leak in '" . (string) ($rule['id'] ?? '?') . "': " . implode(', ', $hits)
                    );
                }
            }
        }
    }

    /**
     * Every scan-worthy served string in one rule-shaped array: the body, each header name/value,
     * the Set-Cookie NAME emitted verbatim, and the taunt comment-syntax strings written into the
     * body (see Response\RouteTemplateEmulator). A `branch` rule ALSO serves each case's response
     * and the default's response when a case fires, and a `traversal-read` rule serves each allow
     * entry's `content` when a path hits, so both are descended into (neither reaches the top-level
     * body). Those nested nodes are themselves body+headers shaped, so the same extraction covers
     * them; the recursion terminates because a branch response / traversal-read content carries
     * neither `branch` nor `traversal-read`.
     *
     * @param array<string,mixed> $src
     * @return string[]
     */
    private function servedTexts(array $src): array
    {
        $texts = [(string) ($src['body'] ?? '')];
        foreach ((array) ($src['headers'] ?? []) as $name => $value) {
            $texts[] = (string) $name;
            $texts[] = (string) $value;
        }
        $texts[] = (string) ($src['set_cookie'] ?? '');
        if (isset($src['taunt']) && is_array($src['taunt'])) {
            foreach (['open', 'close', 'key'] as $part) {
                $texts[] = (string) ($src['taunt'][$part] ?? '');
            }
        }
        if (isset($src['branch']) && is_array($src['branch'])) {
            foreach ((array) ($src['branch']['cases'] ?? []) as $case) {
                if (is_array($case) && isset($case['response']) && is_array($case['response'])) {
                    $texts = array_merge($texts, $this->servedTexts($case['response']));
                }
            }
            if (isset($src['branch']['default']['response']) && is_array($src['branch']['default']['response'])) {
                $texts = array_merge($texts, $this->servedTexts($src['branch']['default']['response']));
            }
        }
        // A `traversal-read` rule serves each allow entry's `content` (and the default's) when a
        // path hits — a synthesized file body under a nested key. Descend into every one so a fetched
        // param artifact with a leak in a traversal-read body is rejected fetch-time, fail-closed like
        // branch/route. A content carries no `traversal-read`, so the recursion terminates.
        if (isset($src['traversal-read']) && is_array($src['traversal-read'])) {
            foreach ((array) ($src['traversal-read']['allow'] ?? []) as $entry) {
                if (is_array($entry) && isset($entry['content']) && is_array($entry['content'])) {
                    $texts = array_merge($texts, $this->servedTexts($entry['content']));
                }
            }
            if (isset($src['traversal-read']['default']['content']) && is_array($src['traversal-read']['default']['content'])) {
                $texts = array_merge($texts, $this->servedTexts($src['traversal-read']['default']['content']));
            }
        }
        // An `arith-eval` rule serves its `response` on a computed hit — a nested node the top-level
        // body never carries, so descend into it. A response carries no `arith-eval`, so this ends.
        if (isset($src['arith-eval']['response']) && is_array($src['arith-eval']['response'])) {
            $texts = array_merge($texts, $this->servedTexts($src['arith-eval']['response']));
        }
        // An `iterate` rule serves the wrap open/close body, the per-sub-call `item`, the `response`
        // headers on the multicall success path, and the `empty`/`fallback` responses — nested
        // served shapes, descended into so a fetched artifact with a leak in any of them is rejected
        // fetch-time. None carries `iterate`, so this ends.
        if (isset($src['iterate']) && is_array($src['iterate'])) {
            $it = $src['iterate'];
            $texts[] = (string) ($it['wrap']['open'] ?? '');
            $texts[] = (string) ($it['wrap']['close'] ?? '');
            if (isset($it['item']) && is_array($it['item'])) {
                $texts = array_merge($texts, $this->servedTexts($it['item']));
            }
            if (isset($it['response']) && is_array($it['response'])) {
                $texts = array_merge($texts, $this->servedTexts($it['response']));
            }
            foreach (['empty', 'fallback'] as $k) {
                if (isset($it[$k]['response']) && is_array($it[$k]['response'])) {
                    $texts = array_merge($texts, $this->servedTexts($it[$k]['response']));
                }
            }
        }

        return $texts;
    }

    // ------------------------------------------------------- coverage counts

    /** @return array<string,int> */
    private function computeCoverage(string $engineDir): array
    {
        $out = [];
        $index = @require $engineDir . '/nuclei-index.full.php';
        if (is_array($index)) {
            $out['routes'] = count((array) ($index['routes'] ?? []));
            $out['templates'] = count((array) ($index['templates'] ?? []));
        }
        $attack = @require $engineDir . '/funnypot-attack.php';
        if (is_array($attack)) {
            $out['attack_rules'] = count($attack);
        }

        return $out;
    }

    /** @return array<string,int> */
    private function packagedCoverage(): array
    {
        if ($this->packagedCoverageOverride !== null) {
            return $this->packagedCoverageOverride;
        }

        $out = [];
        $manifest = $this->readJsonFile(dirname(__DIR__, 2) . '/resources/compiled/manifest.json');
        if (is_array($manifest)) {
            $out['routes'] = (int) ($manifest['route_keys'] ?? 0);
            $out['templates'] = (int) ($manifest['templates_indexed'] ?? 0);
        }
        $attackFile = dirname(__DIR__, 2) . '/resources/compiled/funnypot-attack.php';
        if (is_file($attackFile)) {
            $attack = @require $attackFile;
            $out['attack_rules'] = is_array($attack) ? count($attack) : 0;
        }

        return $out;
    }

    // ------------------------------------------------------- filesystem ops

    private function extractTarball(string $bytes, string $partial): void
    {
        $this->ensureDir($partial);
        $cap = $this->maxExtractedBytes();

        // The gzip ISIZE trailer (uncompressed size mod 2^32) is attacker bytes and trivially
        // forgeable, so it is NO LONGER load-bearing — kept only as a cheap FAST-REJECT for a bomb
        // that honestly admits its size. The real bound is the streaming byte counter below.
        if (strlen($bytes) >= 4) {
            $trailer = unpack('V', substr($bytes, -4));
            if (($trailer[1] ?? 0) > $cap) {
                throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Release decompresses beyond the size cap.');
            }
        }

        // Stream-inflate the fetched .gz with a RUNNING decompressed-byte counter, writing the plain
        // .tar out as it is produced. The instant the counter exceeds the cap, abort — a signed (or
        // replayed, or signer-compromised) gzip bomb with a forged small ISIZE can no longer fill the
        // disk, because extraction now happens on a SIZE-VERIFIED tar, not the raw .gz. Fail closed on
        // a missing zlib, an inflate error, or a stream that ends before the gzip trailer.
        if (!function_exists('inflate_init')) {
            throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'ext-zlib is not loaded; refusing to trust the gzip ISIZE trailer.');
        }
        $tarPath = $partial . '/release.tar';
        $inflate = @inflate_init(ZLIB_ENCODING_GZIP);
        $fh = @fopen($tarPath, 'wb');
        if ($inflate === false || $fh === false) {
            if ($fh !== false) {
                fclose($fh);
            }
            @unlink($tarPath);
            throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Cannot stage the tarball.');
        }
        $total = 0;
        $len = strlen($bytes);
        $chunkSize = 256 * 1024;
        $failure = null;
        for ($offset = 0; $offset < $len; $offset += $chunkSize) {
            $isLast = ($offset + $chunkSize) >= $len;
            $out = @inflate_add($inflate, substr($bytes, $offset, $chunkSize), $isLast ? ZLIB_FINISH : ZLIB_NO_FLUSH);
            if ($out === false) {
                $failure = 'Release gzip stream is corrupt.';
                break;
            }
            $total += strlen($out);
            if ($total > $cap) {
                $failure = 'Release decompresses beyond the size cap.';
                break;
            }
            if ($out !== '' && @fwrite($fh, $out) === false) {
                $failure = 'Cannot stage the tarball.';
                break;
            }
        }
        if ($failure === null && inflate_get_status($inflate) !== ZLIB_STREAM_END) {
            // A truncated/incomplete gzip inflated without error but never reached its trailer.
            $failure = 'Release gzip stream ended before completion.';
        }
        fclose($fh);
        if ($failure !== null) {
            @unlink($tarPath);
            throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, $failure);
        }

        try {
            $phar = new PharData($tarPath);
            foreach (new \RecursiveIteratorIterator($phar) as $file) {
                $name = str_replace('\\', '/', (string) $file->getFileName());
                $inner = (string) $file->getPathname();
                if (strpos($inner, '..') !== false || strpos($name, '..') !== false) {
                    throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Tarball entry escapes its root.');
                }
            }
            $phar->extractTo($partial . '/x', null, true);
        } catch (RulesUpdateException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Tarball extract failed: ' . $e->getMessage());
        }

        // Normalise: everything the manifest references is relative to the extracted root.
        // Move the extracted tree up so <partial>/engine/... is the layout the rest expects.
        $this->rename($partial . '/x', $partial . '/root');
        @unlink($tarPath);
        // Flatten <partial>/root/* to <partial>/*
        foreach (scandir($partial . '/root') ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $this->rename($partial . '/root/' . $item, $partial . '/' . $item);
        }
        @rmdir($partial . '/root');
    }

    /**
     * Recursively list regular files under $base as '/'-joined relative paths. Rejects ANY symlink
     * outright (a tar symlink entry could otherwise redirect a later write outside the tree) and
     * enforces the file-count + total-size floors against a decompression bomb.
     *
     * @return string[]
     */
    private function listTreeFiles(string $base): array
    {
        $out = [];
        $size = 0;
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($base, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $item) {
            if ($item->isLink()) {
                throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Release contains a symlink.');
            }
            if (!$item->isFile()) {
                continue;
            }
            if (count($out) >= self::MAX_ENTRIES) {
                throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Release exceeds the file-count cap.');
            }
            $size += (int) $item->getSize();
            if ($size > $this->maxExtractedBytes()) {
                throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Release exceeds the size cap.');
            }
            $out[] = ltrim(str_replace('\\', '/', substr($item->getPathname(), strlen($base) + 1)), '/');
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $files rel-path => sha256
     */
    private function verifyFileHashes(string $partial, array $files): void
    {
        if ($files === []) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest lists no files.');
        }
        foreach ($files as $rel => $expected) {
            $path = $partial . '/' . ltrim((string) $rel, '/');
            if (strpos((string) $rel, '..') !== false) {
                throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest path escapes its root.');
            }
            if (!is_file($path)) {
                throw new RulesUpdateException(RulesUpdateException::REASON_SHA_MISMATCH, "Manifest lists a missing file: {$rel}.");
            }
            $actual = hash_file('sha256', $path);
            if (!hash_equals(strtolower((string) $expected), strtolower((string) $actual))) {
                throw new RulesUpdateException(RulesUpdateException::REASON_SHA_MISMATCH, "sha256 mismatch for {$rel}.");
            }
        }
    }

    private function promotePartial(string $partial, string $releaseDir): void
    {
        if (is_dir($releaseDir)) {
            $this->rmrf($releaseDir);
        }
        $this->rename($partial, $releaseDir);
    }

    /** Atomic swap of the `current` symlink to point at $engineDir, then bust caches. */
    private function activate(string $engineDir): void
    {
        $current = $this->dataDir . '/current';
        $tmp = $this->dataDir . '/current.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
        @unlink($tmp);
        if (!@symlink($engineDir, $tmp)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_SWAP_FAILED, 'Could not create the swap symlink.');
        }
        if (!@rename($tmp, $current)) {
            @unlink($tmp);
            throw new RulesUpdateException(RulesUpdateException::REASON_SWAP_FAILED, 'Could not activate the new release.');
        }

        // Invalidate opcache + drop this process's parsed-index cache. NOTE: this runs in the updater
        // (CLI/cron) process and CANNOT reach live php-fpm / RoadRunner workers — those keep serving
        // the pre-swap rules until they recycle or are signalled to reload (see docs/RULES-UPDATE.md).
        // A future realpath-keyed PhpArrayStore cache would let live workers self-invalidate.
        if (function_exists('opcache_invalidate')) {
            foreach (self::ENGINE_ARTIFACTS as $artifact) {
                @opcache_invalidate($current . '/' . $artifact, true);
                @opcache_invalidate($engineDir . '/' . $artifact, true);
            }
        }
        PhpArrayStore::forget();
    }

    private function prune(string $keepReleaseDir): void
    {
        $releasesRoot = $this->dataDir . '/releases';
        $dirs = [];
        foreach (scandir($releasesRoot) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $releasesRoot . '/' . $item;
            if (is_dir($path)) {
                $dirs[$path] = @filemtime($path) ?: 0;
            }
        }
        arsort($dirs);
        $kept = 0;
        foreach (array_keys($dirs) as $path) {
            $kept++;
            if ($kept <= $this->retention || $path === $keepReleaseDir) {
                continue;
            }
            $this->rmrf($path);
        }
    }

    /** @return string[] retained version dirs, newest first */
    private function retainedVersions(): array
    {
        $releasesRoot = $this->dataDir . '/releases';
        if (!is_dir($releasesRoot)) {
            return [];
        }
        $dirs = [];
        foreach (scandir($releasesRoot) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $releasesRoot . '/' . $item;
            if (is_dir($path)) {
                $meta = $this->readJsonFile($path . '/meta.json');
                $dirs[(string) ($meta['version'] ?? $item)] = @filemtime($path) ?: 0;
            }
        }
        arsort($dirs);

        return array_keys($dirs);
    }

    // ------------------------------------------------------------ state I/O

    private function writeReleaseMeta(string $releaseDir, string $version, int $seq, ?string $keyId, array $coverage): void
    {
        $this->atomicWrite($releaseDir . '/meta.json', $this->json([
            'version' => $version,
            'version_seq' => $seq,
            'key_id' => $keyId,
            'coverage' => $coverage,
            'installed_at' => gmdate('c'),
        ]));
    }

    /** @return array<string,mixed> */
    private function readState(): array
    {
        return $this->readJsonFile($this->dataDir . '/state.json') ?? [];
    }

    private function writeState(array $state): void
    {
        $this->ensureDir($this->dataDir);
        $this->atomicWrite($this->dataDir . '/state.json', $this->json($state));
    }

    private function touchChecked(array $state, ?string $channelGeneratedAt): void
    {
        $state['checked_at'] = $this->nowStamp();
        if ($channelGeneratedAt !== null) {
            $state['channel_generated_at'] = $channelGeneratedAt;
        }
        $this->writeState($state);
    }

    // ------------------------------------------------------------- helpers

    private function assetUrl(string $tag, string $asset): string
    {
        return $this->repoBaseUrl . '/releases/download/' . rawurlencode($tag) . '/' . $asset;
    }

    private function safeVersionDir(string $version): string
    {
        // A version tag lands as a directory name; keep it to a safe leaf.
        $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $version);

        return $safe === '' ? 'unknown' : $safe;
    }

    /** @return resource|null the held lock handle, or null if another run holds it */
    private function acquireLock()
    {
        $this->ensureDir($this->dataDir);
        $fh = @fopen($this->dataDir . '/.lock', 'c');
        if ($fh === false) {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, 'Cannot open the lock file (data dir not writable?).');
        }
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);

            return null;
        }

        return $fh;
    }

    /** @param resource $fh */
    private function releaseLock($fh): void
    {
        if (is_resource($fh)) {
            @flock($fh, LOCK_UN);
            @fclose($fh);
        }
    }

    private function ensureDir(string $dir): void
    {
        // 0755, NOT 0777: the dir holds require'd PHP; the web user must not be able to write it.
        if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "Cannot create data dir: {$dir}");
        }
    }

    private function rename(string $from, string $to): void
    {
        if (!@rename($from, $to)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_SWAP_FAILED, "Rename failed: {$from} -> {$to}");
        }
    }

    private function atomicWrite(string $path, string $contents): void
    {
        $tmp = $path . '.tmp.' . getmypid() . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, $contents) === false) {
            throw new RulesUpdateException(RulesUpdateException::REASON_SWAP_FAILED, "Write failed: {$tmp}");
        }
        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            throw new RulesUpdateException(RulesUpdateException::REASON_SWAP_FAILED, "Rename failed: {$path}");
        }
    }

    /** @return array<string,mixed>|null */
    private function readJsonFile(string $path): ?array
    {
        if (!is_file($path)) {
            return null;
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $data = json_decode($raw, true);

        return is_array($data) ? $data : null;
    }

    private function json(array $data): string
    {
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
    }

    private function rmrf(string $dir): void
    {
        if (is_link($dir)) {
            @unlink($dir);

            return;
        }
        if (!is_dir($dir)) {
            @unlink($dir);

            return;
        }
        foreach (scandir($dir) ?: [] as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . '/' . $item;
            if (is_link($path)) {
                @unlink($path);
            } elseif (is_dir($path)) {
                $this->rmrf($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($dir);
    }
}
