<?php

declare(strict_types=1);

namespace Funnypot\Rules;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\Store\PhpArrayStore;
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

            // 1. Resolve the target version (explicit pin, else the signed channels pointer).
            $target = $this->pinnedVersion ?? $this->resolveChannelVersion();

            // 2. Fetch + verify the manifest (the signed root).
            [$manifest, $keyId] = $this->fetchVerifiedManifest($target);
            $version = (string) $manifest['version'];
            $seq = (int) $manifest['version_seq'];

            // 3. No-op if already current — before any tarball download.
            if ($currentVersion === $version) {
                $this->touchChecked($state);

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
                'applied_at' => gmdate('c'),
                'checked_at' => gmdate('c'),
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
                'applied_at' => gmdate('c'),
                'checked_at' => $state['checked_at'] ?? gmdate('c'),
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
            $this->retainedVersions()
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

        $keyId = $this->verifier->verify($manifestBytes, $this->normaliseSignature($sig));

        $manifest = json_decode($manifestBytes, true);
        if (!is_array($manifest)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest is not valid JSON.');
        }
        foreach (['schema', 'version', 'version_seq', 'tarball', 'tarball_sha256', 'files'] as $field) {
            if (!isset($manifest[$field])) {
                throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "Manifest is missing '{$field}'.");
            }
        }
        if ((int) $manifest['schema'] !== 1) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Unsupported manifest schema.');
        }
        // The manifest's own version must match the tag we asked for (no bait-and-switch).
        if ((string) $manifest['version'] !== $version) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'Manifest version does not match the requested tag.');
        }

        return [$manifest, $keyId];
    }

    private function resolveChannelVersion(): string
    {
        $bytes = $this->fetcher->get($this->assetUrl('channels', 'channels.json'));
        $sig = $this->fetcher->get($this->assetUrl('channels', 'channels.json.sig'));
        $this->verifier->verify($bytes, $this->normaliseSignature($sig));

        $channels = json_decode($bytes, true);
        if (!is_array($channels)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'channels.json is not valid JSON.');
        }
        $version = (string) ($channels[$this->channel] ?? '');
        if ($version === '') {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "Channel '{$this->channel}' is not defined in channels.json.");
        }
        if (in_array($version, (array) ($channels['revoked'] ?? []), true)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_DOWNGRADE, "Version {$version} is revoked.");
        }

        return $version;
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

        // (b) ReDoS budget on every incoming regex condition (runs on attacker input at runtime).
        $this->redos->inspectRules($rules);

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
     * and the default's response when a case fires, so those are descended into (they never reach
     * the top-level body). Branch responses are themselves body+headers shaped, so the same
     * extraction covers them; the recursion terminates because a branch response carries no `branch`.
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
        // Bound the decompressed size up front via the gzip ISIZE trailer (uncompressed size mod
        // 2^32) so a signed gzip bomb cannot fill the disk during extraction. listTreeFiles()
        // enforces the count/size caps afterward as belt-and-braces.
        if (strlen($bytes) >= 4) {
            $trailer = unpack('V', substr($bytes, -4));
            if (($trailer[1] ?? 0) > self::MAX_EXTRACTED_BYTES) {
                throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Release decompresses beyond the size cap.');
            }
        }
        $this->ensureDir($partial);
        $tarPath = $partial . '/release.tar.gz';
        if (@file_put_contents($tarPath, $bytes) === false) {
            throw new RulesUpdateException(RulesUpdateException::REASON_EXTRACT_FAILED, 'Cannot stage the tarball.');
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
            if ($size > self::MAX_EXTRACTED_BYTES) {
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

    private function touchChecked(array $state): void
    {
        $state['checked_at'] = gmdate('c');
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
