#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Package + sign a funnypot-rules release from funnypot-core's already-gated compiled
 * artifacts. Produces exactly the asset shape RulesUpdater fetches and verifies:
 *
 *   <out>/<version>.manifest.json        signed root: schema, version, version_seq, tarball,
 *                                          tarball_sha256, per-file sha256
 *   <out>/<version>.manifest.json.sig    raw ed25519 detached signature over the manifest bytes
 *   <out>/funnypot-rules-<version>.tar.gz engine/<artifact>.php tree
 *   <out>/channels.json + .sig            stable/latest -> version pointer (also signed)
 *
 * The workflow (publish-rules.yml) uploads these to a GitHub Release tagged <version> and to a
 * rolling `channels` release. This script NEVER compiles — it only republishes bytes that
 * funnypot-core CI already produced, tested, and gated. Signing is the LAST step, so a
 * signature attests that the fingerprint-safety + license gates passed on this exact commit.
 *
 *   FUNNYPOT_RULES_SIGNING_KEY  base64 of the 64-byte ed25519 secret key (CI secret)
 *   FUNNYPOT_RULES_VERSION      optional; default v<UTC date>-<short git sha>
 *   FUNNYPOT_RULES_SEQ          optional monotonic integer; default current unix time
 *
 *   php scripts/ci/publish-rules-release.php [--out=DIR]
 */

$root = dirname(__DIR__, 2);

if (!function_exists('sodium_crypto_sign_detached')) {
    fwrite(STDERR, "ext-sodium is required to sign a release.\n");
    exit(2);
}

$out = $root . '/dist-release';
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--out=', 6) === 0) {
        $out = substr($arg, 6);
    }
}
if (!is_dir($out) && !mkdir($out, 0755, true) && !is_dir($out)) {
    fwrite(STDERR, "cannot create out dir: {$out}\n");
    exit(2);
}

$secretB64 = getenv('FUNNYPOT_RULES_SIGNING_KEY') ?: '';
$secret = base64_decode($secretB64, true);
if ($secret === false || strlen($secret) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
    fwrite(STDERR, "FUNNYPOT_RULES_SIGNING_KEY must be base64 of a 64-byte ed25519 secret key.\n");
    exit(2);
}

$shortSha = trim((string) @shell_exec('git -C ' . escapeshellarg($root) . ' rev-parse --short HEAD 2>/dev/null'));
$version = getenv('FUNNYPOT_RULES_VERSION') ?: ('v' . gmdate('Y.m.d') . ($shortSha !== '' ? '-' . $shortSha : ''));
$seq = (int) (getenv('FUNNYPOT_RULES_SEQ') ?: time());

// The engine artifacts funnypot-core reads; each must exist and be a pure literal.
$artifacts = ['nuclei-index.full.php', 'funnypot-attack.php', 'funnypot-routes.php', 'funnypot-routes-index.php'];

// Stage engine/<artifact> and validate each is inert before it is ever shipped.
require $root . '/vendor/autoload.php';
$validator = new Funnypot\Rules\PhpLiteralValidator();

$stage = $out . '/stage';
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
    'schema' => 1,
    'version' => $version,
    'version_seq' => $seq,
    'built_at' => gmdate('c'),
    'built_from_commit' => $shortSha,
    'key_id' => getenv('FUNNYPOT_RULES_KEY_ID') ?: 'unknown',
    'tarball' => $tarballName,
    'tarball_sha256' => hash('sha256', $tarballBytes),
    'files' => $files,
    'sources' => $sources,
];

$manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
$manifestSig = sodium_crypto_sign_detached($manifestBytes, $secret);
file_put_contents($out . '/' . $version . '.manifest.json', $manifestBytes);
file_put_contents($out . '/' . $version . '.manifest.json.sig', $manifestSig);

// Channels pointer (also signed). A promotion job can later hold `stable` behind `latest`.
$channels = ['schema' => 1, 'latest' => $version, 'stable' => $version, 'revoked' => []];
$channelsBytes = json_encode($channels, JSON_UNESCAPED_SLASHES);
file_put_contents($out . '/channels.json', $channelsBytes);
file_put_contents($out . '/channels.json.sig', sodium_crypto_sign_detached($channelsBytes, $secret));

// Clean up the stage tree.
foreach ($artifacts as $artifact) {
    @unlink($stage . '/engine/' . $artifact);
}
@rmdir($stage . '/engine');
@rmdir($stage);

fwrite(STDOUT, "version={$version}\n");
fwrite(STDOUT, "seq={$seq}\n");
fwrite(STDOUT, "tarball={$tarballName}\n");
fwrite(STDOUT, "out={$out}\n");
exit(0);
