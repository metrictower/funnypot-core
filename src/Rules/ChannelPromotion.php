<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Publish ≠ promote (FP-0331). The pure core of the rules publisher's channel-pointer handling,
 * split out of scripts/ci/publish-rules-release.php so it is unit-testable without secrets or a real
 * release: it VERIFIES a base channels.json against a channels-role key before trusting it, then
 * moves exactly ONE pointer (`latest` or `stable`) while carrying `revoked` and the untouched pointer
 * forward verbatim. It NEVER signs (the CLI wrapper holds the secret and re-signs the returned bytes)
 * and NEVER edits `revoked` (revocation is a separate, out-of-band action).
 *
 * Fail-closed by construction: every method verifies the signature FIRST and only then decodes and
 * trusts the payload. There is no catch arm and no default/fallback return — any verification or
 * validation failure throws, so an invalid, forged, or missing base can never degrade into a reset
 * `revoked=[]` / re-pointed doc (the very bug this ticket removes).
 *
 * PHP 7.3 floor (this is engine/library code): no typed properties, no arrow functions, no
 * `str_contains`/`match`/named arguments. Mirror the KeyRing/SignatureVerifier style.
 */
final class ChannelPromotion
{
    /** @var SignatureVerifier */
    private $verifier;

    public function __construct(SignatureVerifier $verifier)
    {
        $this->verifier = $verifier;
    }

    /**
     * Verify the signed base channels doc, then return a new channels array with the one requested
     * pointer moved to $version and everything else (the other pointer, `revoked`, any unknown field)
     * carried forward. Only `generated_at`/`expires` are re-stamped; `schema` is untouched.
     *
     * @param string      $baseJson     the current channels.json bytes
     * @param string      $baseSig      its detached signature (raw 64-byte, or base64/hex-encoded)
     * @param string      $promote      'latest' | 'stable' — which pointer to move
     * @param string      $version      the version to point at
     * @param int         $now          current unix time (freshness re-stamp + key-window check)
     * @param int         $ttlDays      channels freshness window in days
     * @param string|null $expectLatest optional compare-and-swap guard: refuse unless base latest == this
     * @param string|null $expectStable optional compare-and-swap guard: refuse unless base stable == this
     *
     * @return array<string,mixed> the new channels doc (unsigned)
     *
     * @throws RulesUpdateException on any verification or validation failure (fail-closed)
     */
    public function carryForward(
        string $baseJson,
        string $baseSig,
        string $promote,
        string $version,
        int $now,
        int $ttlDays,
        ?string $expectLatest = null,
        ?string $expectStable = null
    ): array {
        // 1. Trust nothing until the base signature verifies under a channels-role key (throws on fail).
        $this->verifier->verify(
            $baseJson,
            self::normaliseSignature($baseSig),
            SignatureVerifier::CONTEXT_CHANNELS,
            SignatureVerifier::ROLE_CHANNELS,
            $now
        );

        $base = json_decode($baseJson, true);
        if (!is_array($base)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'base channels.json is not a JSON object.');
        }

        if ($promote !== 'latest' && $promote !== 'stable') {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "unknown promote target '{$promote}' (expected latest|stable).");
        }

        // 2. Compare-and-swap: refuse if the base pointer is not what the caller expected (another
        //    promotion moved it under us — distinguishes authenticity from current-authority).
        $baseLatest = (string) ($base['latest'] ?? '');
        $baseStable = (string) ($base['stable'] ?? '');
        if ($expectLatest !== null && $baseLatest !== $expectLatest) {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "base latest '{$baseLatest}' != expected '{$expectLatest}' (stale base).");
        }
        if ($expectStable !== null && $baseStable !== $expectStable) {
            throw new RulesUpdateException(RulesUpdateException::REASON_CONFIG, "base stable '{$baseStable}' != expected '{$expectStable}' (stale base).");
        }

        // 3. Never point a channel at a revoked version (no resurrection). Fail up front rather than
        //    publish a self-contradictory pointer the consumer would reject as a downgrade.
        $revoked = (array) ($base['revoked'] ?? []);
        if (in_array($version, $revoked, true)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_DOWNGRADE, "refusing to promote a revoked version: {$version}.");
        }

        // 4. stable may never lead latest: stable can only be moved to the version latest already holds.
        if ($promote === 'stable' && $baseLatest !== $version) {
            throw new RulesUpdateException(RulesUpdateException::REASON_DOWNGRADE, "refusing to move stable to {$version}: stable may not lead latest ({$baseLatest}).");
        }

        // 5. Carry the whole base forward (preserves unknown fields); overwrite only the one pointer
        //    and the freshness window. schema and the untouched pointer are left exactly as signed.
        $new = $base;
        $new[$promote] = $version;
        $new['generated_at'] = gmdate('c', $now);
        $new['expires'] = gmdate('c', $now + $ttlDays * 86400);

        return $new;
    }

    /**
     * Promote-only guard: a pointer may only be moved to a version whose signed manifest actually
     * exists. Verify $manifestJson with the RELEASE key over the manifest context, then assert the
     * manifest's `version` equals $version.
     *
     * @throws RulesUpdateException if the manifest fails to verify or names a different version
     */
    public function verifyManifestVersion(string $manifestJson, string $manifestSig, string $version, int $now): void
    {
        $this->verifier->verify(
            $manifestJson,
            self::normaliseSignature($manifestSig),
            SignatureVerifier::CONTEXT_MANIFEST,
            SignatureVerifier::ROLE_RELEASE,
            $now
        );

        $manifest = json_decode($manifestJson, true);
        if (!is_array($manifest)) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, 'manifest is not a JSON object.');
        }
        $got = (string) ($manifest['version'] ?? '');
        if ($got !== $version) {
            throw new RulesUpdateException(RulesUpdateException::REASON_BAD_MANIFEST, "manifest version '{$got}' != promote target '{$version}'.");
        }
    }

    /**
     * Which output files a given mode writes. Pure (no I/O) so "promote=none writes NO channels.json"
     * — the headline fix — is unit-assertable. `artifacts` = the versioned tarball + manifest(+sig).
     *
     * @return array{artifacts:bool,channels:bool}
     */
    public static function planWrites(bool $promoteOnly, string $promote, bool $bootstrap): array
    {
        if ($promoteOnly) {
            // Promote-only never repackages — it only moves a pointer over an already-published version.
            return ['artifacts' => false, 'channels' => true];
        }

        return ['artifacts' => true, 'channels' => ($promote !== 'none' || $bootstrap)];
    }

    /**
     * Accept the publisher's raw 64-byte detached signature, or a base64/hex-encoded one. NEVER trim a
     * raw signature: an ed25519 signature can start or end with a byte whose value is whitespace, and
     * trimming would corrupt it (mirrors RulesUpdater::normaliseSignature).
     */
    private static function normaliseSignature(string $sig): string
    {
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

        // Fall through with the original bytes; verify() rejects a wrong-length signature.
        return $sig;
    }
}
