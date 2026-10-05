#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Package + sign a funnypot-rules release from funnypot-core's already-gated compiled
 * artifacts, and/or move a channel pointer. Produces the asset shape RulesUpdater fetches:
 *
 *   <out>/<version>.manifest.json        signed root: schema, version, version_seq, tarball,
 *                                          tarball_sha256, per-file sha256
 *   <out>/<version>.manifest.json.sig    raw ed25519 detached signature over the manifest bytes
 *   <out>/funnypot-rules-<version>.tar.gz engine/<artifact>.php tree
 *   <out>/channels.json + .sig            stable/latest -> version pointer (also signed)
 *
 * PUBLISH ≠ PROMOTE (FP-0331). Publishing a version does NOT move a live pointer unless asked:
 *   --promote=none  (default)  package + sign the version; write NO channels.json at all.
 *   --promote=latest|stable    ALSO move that one pointer, carrying the other pointer + the
 *                              `revoked` list forward from a VERIFIED base (--channels-in). stable
 *                              may only ever point at the version `latest` already holds.
 *   --promote-only=VERSION     move a pointer over an already-published version, NO repackaging:
 *                              verify <out>/<VERSION>.manifest.json with the release key, then
 *                              carry the base channels forward. Needs --promote=latest|stable.
 *   --bootstrap                first-ever channels doc only: mint latest=stable=version, revoked=[].
 *                              Refuses if a base (--channels-in) exists; needs an explicit --promote.
 * A missing/forged/invalid base is a HARD error — never a silent `revoked=[]` reset.
 *
 * The workflow (publish-rules.yml) uploads the version assets to a GitHub Release tagged <version>,
 * and (only when a pointer moves) channels.json to a rolling `channels` release. This script NEVER
 * compiles — it only republishes bytes funnypot-core CI already produced, tested, and gated. Signing
 * is the LAST step, so a signature attests the fingerprint-safety + license gates passed on this
 * exact commit. The channel-pointer logic itself lives in (and is unit-tested via) the pure
 * Funnypot\Core\Rules\ChannelPromotion class.
 *
 *   FUNNYPOT_RULES_SIGNING_KEY           base64 of the 64-byte ed25519 RELEASE secret key (CI secret,
 *                                        role 'release' — signs <version>.manifest.json). Required
 *                                        only when packaging a version (NOT in --promote-only).
 *   FUNNYPOT_RULES_CHANNELS_SIGNING_KEY  base64 of the 64-byte ed25519 CHANNELS secret key (CI secret,
 *                                        role 'channels' — signs channels.json). A SEPARATE key from
 *                                        the release key: one stolen secret can move the pointer OR
 *                                        sign a release, never both. Required only when a pointer
 *                                        moves (--promote!=none or --promote-only); NOT for
 *                                        --promote=none.
 *   FUNNYPOT_RULES_CHANNELS_PUBKEY       base64 of the 32-byte ed25519 CHANNELS public key, used to
 *                                        VERIFY --channels-in before carrying it forward (or
 *                                        --channels-pubkey=).
 *   FUNNYPOT_RULES_PUBKEY                base64 of the 32-byte ed25519 RELEASE public key, used by
 *                                        --promote-only to verify the target manifest (or
 *                                        --release-pubkey=).
 *   FUNNYPOT_RULES_VERSION               optional; default v<UTC date>-<short git sha>
 *   FUNNYPOT_RULES_SEQ                   optional monotonic integer; default current unix time
 *   FUNNYPOT_RULES_MANIFEST_TTL_DAYS     optional; freshness window on the manifest (default 90)
 *   FUNNYPOT_RULES_CHANNELS_TTL_DAYS     optional; freshness window on channels.json (default 7).
 *                                        channels MUST be re-signed at least every TTL by a scheduled
 *                                        job or every fleet goes 'stale-metadata' (fail-safe: last-good
 *                                        keeps serving; the distinct reason pages the publisher).
 *
 *   php scripts/ci/publish-rules-release.php [--out=DIR] [--promote=none|latest|stable]
 *       [--channels-in=DIR] [--channels-pubkey=B64] [--release-pubkey=B64]
 *       [--promote-only=VERSION] [--bootstrap] [--expect-latest=V] [--expect-stable=V]
 */

$root = dirname(__DIR__, 2);

if (!function_exists('sodium_crypto_sign_detached')) {
    fwrite(STDERR, "ext-sodium is required to sign a release.\n");
    exit(2);
}

// ---- CLI flags (publish ≠ promote) --------------------------------------------------------------
$out = $root . '/dist-release';
$promote = 'none';            // none | latest | stable — which pointer, if any, to move
$channelsIn = null;           // dir holding the base channels.json + .sig to carry forward
$channelsPubB64 = getenv('FUNNYPOT_RULES_CHANNELS_PUBKEY') ?: '';
$releasePubB64 = getenv('FUNNYPOT_RULES_PUBKEY') ?: '';
$promoteOnlyVersion = null;   // non-null => promote-only mode (move a pointer, NO repackaging)
$bootstrap = false;           // explicit first-ever channels doc (no base)
$expectLatest = null;         // compare-and-swap guard: refuse unless base latest == this
$expectStable = null;         // compare-and-swap guard: refuse unless base stable == this
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--out=', 6) === 0) {
        $out = substr($arg, 6);
    } elseif (strncmp($arg, '--promote=', 10) === 0) {
        $promote = substr($arg, 10);
    } elseif (strncmp($arg, '--channels-in=', 14) === 0) {
        $channelsIn = substr($arg, 14);
    } elseif (strncmp($arg, '--channels-pubkey=', 18) === 0) {
        $channelsPubB64 = substr($arg, 18);
    } elseif (strncmp($arg, '--release-pubkey=', 17) === 0) {
        $releasePubB64 = substr($arg, 17);
    } elseif (strncmp($arg, '--promote-only=', 15) === 0) {
        $promoteOnlyVersion = substr($arg, 15);
    } elseif ($arg === '--bootstrap') {
        $bootstrap = true;
    } elseif (strncmp($arg, '--expect-latest=', 16) === 0) {
        $expectLatest = substr($arg, 16);
    } elseif (strncmp($arg, '--expect-stable=', 16) === 0) {
        $expectStable = substr($arg, 16);
    } else {
        fwrite(STDERR, "unknown argument: {$arg}\n");
        exit(2);
    }
}
if (!in_array($promote, ['none', 'latest', 'stable'], true)) {
    fwrite(STDERR, "--promote must be none|latest|stable\n");
    exit(2);
}
if (!is_dir($out) && !mkdir($out, 0755, true) && !is_dir($out)) {
    fwrite(STDERR, "cannot create out dir: {$out}\n");
    exit(2);
}

require $root . '/vendor/autoload.php';

// ---- Mode sanity + which files this invocation writes -------------------------------------------
$promoteOnly = $promoteOnlyVersion !== null;
if ($promoteOnly && $promote === 'none') {
    fwrite(STDERR, "--promote-only needs --promote=latest|stable (which pointer to move).\n");
    exit(2);
}
if ($bootstrap && $promoteOnly) {
    fwrite(STDERR, "--bootstrap is a publish-mode action; not valid with --promote-only.\n");
    exit(2);
}
if ($bootstrap && $channelsIn !== null) {
    fwrite(STDERR, "--bootstrap must not be combined with --channels-in: it mints a fresh pointer and refuses to clobber an existing base.\n");
    exit(2);
}
if ($bootstrap && $promote === 'none') {
    fwrite(STDERR, "--bootstrap needs an explicit --promote=latest|stable (intent to write the first channels doc).\n");
    exit(2);
}

$plan = \Funnypot\Core\Rules\ChannelPromotion::planWrites($promoteOnly, $promote, $bootstrap);

// ---- Keys, loaded strictly per what this invocation needs (FP-0331 F1) --------------------------
// RELEASE secret: only when we package + sign a version manifest (publish mode, not promote-only).
$secret = null;
if ($plan['artifacts']) {
    $secretB64 = getenv('FUNNYPOT_RULES_SIGNING_KEY') ?: '';
    $secret = base64_decode($secretB64, true);
    if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, "FUNNYPOT_RULES_SIGNING_KEY must be base64 of a 64-byte ed25519 secret key.\n");
        exit(2);
    }
}
// CHANNELS secret: only when we actually write/sign a channels doc. --promote=none needs NEITHER
// this nor any public key — the whole point of the default path.
$channelsSecret = null;
if ($plan['channels']) {
    $channelsSecretB64 = getenv('FUNNYPOT_RULES_CHANNELS_SIGNING_KEY') ?: '';
    $channelsSecret = base64_decode($channelsSecretB64, true);
    if ($channelsSecret === false || strlen($channelsSecret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
        fwrite(STDERR, "FUNNYPOT_RULES_CHANNELS_SIGNING_KEY must be base64 of a 64-byte ed25519 secret key (separate from the release key).\n");
        exit(2);
    }
}
// A verifier over the supplied PUBLIC keys: channels pubkey to verify a carried-forward base, release
// pubkey to verify a promote-only target manifest. Bootstrap verifies nothing (no base).
$promoter = null;
$needChannelsVerify = $plan['channels'] && !$bootstrap; // carryForward verifies the base
$needReleaseVerify = $promoteOnly;                      // verifyManifestVersion
if ($needChannelsVerify || $needReleaseVerify) {
    $ringKeys = [];
    if ($needChannelsVerify) {
        $cpk = base64_decode($channelsPubB64, true);
        if ($cpk === false || strlen($cpk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            fwrite(STDERR, "--channels-pubkey (or FUNNYPOT_RULES_CHANNELS_PUBKEY) must be base64 of a 32-byte ed25519 public key.\n");
            exit(2);
        }
        $ringKeys[] = ['key_id' => 'channels', 'public_key' => base64_encode($cpk), 'valid_from' => null, 'valid_until' => null, 'roles' => ['channels']];
    }
    if ($needReleaseVerify) {
        $rpk = base64_decode($releasePubB64, true);
        if ($rpk === false || strlen($rpk) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            fwrite(STDERR, "--release-pubkey (or FUNNYPOT_RULES_PUBKEY) must be base64 of a 32-byte ed25519 public key.\n");
            exit(2);
        }
        $ringKeys[] = ['key_id' => 'release', 'public_key' => base64_encode($rpk), 'valid_from' => null, 'valid_until' => null, 'roles' => ['release']];
    }
    $promoter = new \Funnypot\Core\Rules\ChannelPromotion(
        new \Funnypot\Core\Rules\SignatureVerifier(new \Funnypot\Core\Rules\KeyRing($ringKeys))
    );
}

$manifestTtlDays = (int) (getenv('FUNNYPOT_RULES_MANIFEST_TTL_DAYS') ?: 90);
$channelsTtlDays = (int) (getenv('FUNNYPOT_RULES_CHANNELS_TTL_DAYS') ?: 7);
$manifestTtlDays = $manifestTtlDays > 0 ? $manifestTtlDays : 90;
$channelsTtlDays = $channelsTtlDays > 0 ? $channelsTtlDays : 7;

$shortSha = trim((string) @shell_exec('git -C ' . escapeshellarg($root) . ' rev-parse --short HEAD 2>/dev/null'));
if ($promoteOnly) {
    $version = $promoteOnlyVersion;
} else {
    $version = getenv('FUNNYPOT_RULES_VERSION') ?: ('v' . gmdate('Y.m.d') . ($shortSha !== '' ? '-' . $shortSha : ''));
}
$seq = (int) (getenv('FUNNYPOT_RULES_SEQ') ?: time());
$nowTs = time();

// ---- Package + sign the version (publish mode only) ---------------------------------------------
$tarballName = null;
$artifacts = ['nuclei-index.full.php', 'funnypot-attack.php', 'funnypot-routes.php', 'funnypot-routes-index.php', 'funnypot-param.php'];
$stage = $out . '/stage';
if ($plan['artifacts']) {
    // The engine artifacts funnypot-core reads; each must exist and be a pure literal. Must stay in
    // lock-step with RulesUpdater::ENGINE_ARTIFACTS — a release missing one is rejected on install.
    $validator = new Funnypot\Core\Rules\PhpLiteralValidator();

    @mkdir($stage . '/engine', 0755, true);
    $files = [];
    foreach ($artifacts as $artifact) {
        $src = $root . '/resources/compiled/' . $artifact;
        if (!is_file($src)) {
            fwrite(STDERR, "missing compiled artifact: {$src}\n");
            exit(1);
        }
        $validator->validateFile($src, $artifact); // refuse to ship a non-literal artifact
        copy($src, $stage . '/engine/' . $artifact);
        $files['engine/' . $artifact] = hash_file('sha256', $src);
    }

    // Build the gzipped tarball (PharData: the same format RulesUpdater extracts).
    $tarballName = 'funnypot-rules-' . $version . '.tar.gz';
    $tarPath = $out . '/build.tar';
    @unlink($tarPath);
    @unlink($tarPath . '.gz');
    $phar = new PharData($tarPath);
    $phar->buildFromDirectory($stage);
    $phar->compress(Phar::GZ);
    unset($phar);
    $tarballBytes = (string) file_get_contents($tarPath . '.gz');
    @unlink($tarPath);
    @unlink($tarPath . '.gz');
    file_put_contents($out . '/' . $tarballName, $tarballBytes);

    // Provenance from funnypot-core's own compile manifest.
    $sources = [];
    $coreManifest = @json_decode((string) @file_get_contents($root . '/resources/compiled/manifest.json'), true);
    if (is_array($coreManifest)) {
        $sources['nuclei-templates'] = ['tag' => $coreManifest['upstream_tag'] ?? null, 'sha' => $coreManifest['upstream_sha'] ?? null];
        $sources['coverage'] = [
            'routes' => (int) ($coreManifest['route_keys'] ?? 0),
            'templates' => (int) ($coreManifest['templates_indexed'] ?? 0),
        ];
    }

    $manifest = [
        'schema' => \Funnypot\Core\SchemaVersion::RELEASE_CURRENT,
        'version' => $version,
        'version_seq' => $seq,
        'generated_at' => gmdate('c', $nowTs),
        'expires' => gmdate('c', $nowTs + $manifestTtlDays * 86400),
        'built_at' => gmdate('c', $nowTs),
        'built_from_commit' => $shortSha,
        'key_id' => getenv('FUNNYPOT_RULES_KEY_ID') ?: 'unknown',
        'tarball' => $tarballName,
        'tarball_sha256' => hash('sha256', $tarballBytes),
        'files' => $files,
        'sources' => $sources,
    ];

    // Domain separation: sign CONTEXT_MANIFEST . bytes with the RELEASE key. The bytes on the wire are
    // unchanged (readable JSON); only the signed message is context-prefixed, so a channels signature
    // can never verify as a manifest signature.
    $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
    $manifestSig = sodium_crypto_sign_detached(\Funnypot\Core\Rules\SignatureVerifier::CONTEXT_MANIFEST . $manifestBytes, $secret);
    file_put_contents($out . '/' . $version . '.manifest.json', $manifestBytes);
    file_put_contents($out . '/' . $version . '.manifest.json.sig', $manifestSig);
}

// ---- Move a channel pointer (only when asked) ---------------------------------------------------
// --promote=none writes NOTHING here — a version is published without touching the live pointers.
if ($plan['channels']) {
    if ($bootstrap) {
        // First-ever release: both pointers at the new version, nothing revoked. No base to carry.
        $channels = [
            'schema' => \Funnypot\Core\SchemaVersion::RELEASE_CURRENT,
            'generated_at' => gmdate('c', $nowTs),
            'expires' => gmdate('c', $nowTs + $channelsTtlDays * 86400),
            'latest' => $version,
            'stable' => $version,
            'revoked' => [],
        ];
    } else {
        if ($channelsIn === null) {
            fwrite(STDERR, "--promote={$promote} needs --channels-in=DIR (the base channels to carry forward); use --bootstrap only for the first-ever release.\n");
            exit(2);
        }
        $baseJson = @file_get_contents(rtrim($channelsIn, '/') . '/channels.json');
        $baseSig = @file_get_contents(rtrim($channelsIn, '/') . '/channels.json.sig');
        if ($baseJson === false || $baseSig === false) {
            fwrite(STDERR, "cannot read the base channels.json(.sig) in {$channelsIn} — refusing to fabricate a pointer.\n");
            exit(1);
        }
        if ($promoteOnly) {
            // A pointer may only move to a version whose signed manifest actually exists.
            $mJson = @file_get_contents($out . '/' . $version . '.manifest.json');
            $mSig = @file_get_contents($out . '/' . $version . '.manifest.json.sig');
            if ($mJson === false || $mSig === false) {
                fwrite(STDERR, "promote-only: cannot read {$version}.manifest.json(.sig) in {$out}.\n");
                exit(1);
            }
            try {
                $promoter->verifyManifestVersion($mJson, $mSig, $version, $nowTs);
            } catch (\Throwable $e) {
                fwrite(STDERR, "promote-only target manifest verify failed (no pointer written): " . $e->getMessage() . "\n");
                exit(1);
            }
        }
        try {
            $channels = $promoter->carryForward($baseJson, $baseSig, $promote, $version, $nowTs, $channelsTtlDays, $expectLatest, $expectStable);
        } catch (\Throwable $e) {
            // Fail closed: an invalid/forged/stale base never degrades into an empty-revoked reset.
            fwrite(STDERR, "channels carry-forward failed (fail-closed, no pointer written): " . $e->getMessage() . "\n");
            exit(1);
        }
    }

    // Channels pointer signed with the CHANNELS key over CONTEXT_CHANNELS . bytes.
    $channelsBytes = json_encode($channels, JSON_UNESCAPED_SLASHES);
    file_put_contents($out . '/channels.json', $channelsBytes);
    file_put_contents($out . '/channels.json.sig', sodium_crypto_sign_detached(\Funnypot\Core\Rules\SignatureVerifier::CONTEXT_CHANNELS . $channelsBytes, $channelsSecret));
}

// Clean up the stage tree (only built in publish mode).
if ($plan['artifacts']) {
    foreach ($artifacts as $artifact) {
        @unlink($stage . '/engine/' . $artifact);
    }
    @rmdir($stage . '/engine');
    @rmdir($stage);
}

fwrite(STDOUT, "version={$version}\n");
fwrite(STDOUT, "seq={$seq}\n");
if ($plan['artifacts']) {
    fwrite(STDOUT, "tarball={$tarballName}\n");
}
fwrite(STDOUT, "promote={$promote}\n");
fwrite(STDOUT, 'channels_written=' . ($plan['channels'] ? '1' : '0') . "\n");
fwrite(STDOUT, "out={$out}\n");
exit(0);
