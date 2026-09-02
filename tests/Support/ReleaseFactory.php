<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Rules\KeyRing;
use Funnypot\Core\Rules\SignatureVerifier;
use Funnypot\Core\SchemaVersion;
use Phar;
use PharData;

/**
 * Builds signed funnypot-rules release fixtures for the updater tests: a gzipped tarball of
 * engine artifacts, a schema-2 manifest that pins their sha256s + a freshness window, and a
 * detached ed25519 signature over the CONTEXT-PREFIXED manifest bytes — all served through an
 * ArrayFetcher at the exact URLs RulesUpdater requests. Owns TWO throwaway ed25519 keypairs (a
 * `release` signer and a `channels` signer) so role separation can be exercised.
 */
final class ReleaseFactory
{
    /** @var string */
    public $baseUrl = 'https://github.com/metrictower/funnypot-rules';

    /** @var string */
    private $releaseSecret;

    /** @var string */
    private $releasePublic;

    /** @var string */
    private $channelsSecret;

    /** @var string */
    private $channelsPublic;

    /** @var string */
    private $workDir;

    /** @var int */
    private $tarSeq = 0;

    public function __construct(string $workDir)
    {
        $release = sodium_crypto_sign_keypair();
        $this->releaseSecret = sodium_crypto_sign_secretkey($release);
        $this->releasePublic = sodium_crypto_sign_publickey($release);
        $channels = sodium_crypto_sign_keypair();
        $this->channelsSecret = sodium_crypto_sign_secretkey($channels);
        $this->channelsPublic = sodium_crypto_sign_publickey($channels);
        $this->workDir = rtrim($workDir, '/');
        @mkdir($this->workDir, 0755, true);
    }

    /** A verifier that trusts exactly this factory's two role-scoped keys. */
    public function verifier(): SignatureVerifier
    {
        return new SignatureVerifier($this->keyRing());
    }

    /** A ring with the release key scoped to role `release` and the channels key to role `channels`. */
    public function keyRing(): KeyRing
    {
        return new KeyRing([
            [
                'key_id' => 'test-release',
                'public_key' => base64_encode($this->releasePublic),
                'valid_from' => '2000-01-01',
                'valid_until' => null,
                'roles' => ['release'],
            ],
            [
                'key_id' => 'test-channels',
                'public_key' => base64_encode($this->channelsPublic),
                'valid_from' => '2000-01-01',
                'valid_until' => null,
                'roles' => ['channels'],
            ],
        ]);
    }

    /**
     * Register a full release (manifest + sig + tarball) with $fetcher under $version. Defaults to a
     * fresh schema-2 envelope signed by the release key over the manifest context; the last two
     * params let a negative test forge a wrong signing context (e.g. '' for a legacy context-free
     * signature) or a wrong signing role ('channels').
     *
     * @param array<string,string> $engineFiles artifactName => PHP file contents
     * @param array<string,mixed>  $manifestOverrides tweak/replace manifest fields for negative tests
     * @return array{version:string,tarball:string,manifest:array<string,mixed>,tarball_bytes:string}
     */
    public function publish(
        ArrayFetcher $fetcher,
        string $version,
        int $seq,
        array $engineFiles,
        array $manifestOverrides = [],
        ?string $signContext = null,
        string $signRole = 'release'
    ): array {
        $tarballName = 'funnypot-rules-' . $version . '.tar.gz';
        $tarballBytes = $this->buildTarball($engineFiles);

        $files = [];
        foreach ($engineFiles as $name => $contents) {
            $files['engine/' . $name] = hash('sha256', $contents);
        }

        $now = time();
        $manifest = array_merge([
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'version' => $version,
            'version_seq' => $seq,
            'generated_at' => gmdate('c', $now),
            'expires' => gmdate('c', $now + 90 * 86400),
            'built_at' => gmdate('c', $now),
            'key_id' => 'test-release',
            'tarball' => $tarballName,
            'tarball_sha256' => hash('sha256', $tarballBytes),
            'files' => $files,
        ], $manifestOverrides);

        $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $context = $signContext ?? SignatureVerifier::CONTEXT_MANIFEST;
        $sig = $this->sign($context, $manifestBytes, $signRole);

        $base = $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/';
        $fetcher->put($base . $version . '.manifest.json', $manifestBytes);
        $fetcher->put($base . $version . '.manifest.json.sig', $sig);
        $fetcher->put($base . $tarballName, $tarballBytes);

        return ['version' => $version, 'tarball' => $tarballName, 'manifest' => $manifest, 'tarball_bytes' => $tarballBytes];
    }

    /**
     * Register a signed channels.json. Defaults to a fresh schema-2 envelope signed by the channels
     * key over the channels context; $overrides replaces envelope fields (e.g. an `expires` in the
     * past for a staleness test), and $signContext/$signRole let a negative test forge a wrong
     * context or sign with the release key.
     *
     * @param array<string,mixed> $channels channel => version map (plus optional revoked/schema/...)
     * @param array<string,mixed> $overrides envelope-field overrides applied last
     */
    public function publishChannels(
        ArrayFetcher $fetcher,
        array $channels,
        array $overrides = [],
        ?string $signContext = null,
        string $signRole = 'channels'
    ): void {
        $now = time();
        $channels = array_merge([
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'generated_at' => gmdate('c', $now),
            'expires' => gmdate('c', $now + 7 * 86400),
        ], $channels, $overrides);

        $bytes = json_encode($channels, JSON_UNESCAPED_SLASHES);
        $context = $signContext ?? SignatureVerifier::CONTEXT_CHANNELS;
        $sig = $this->sign($context, $bytes, $signRole);
        $base = $this->baseUrl . '/releases/download/channels/';
        $fetcher->put($base . 'channels.json', $bytes);
        $fetcher->put($base . 'channels.json.sig', $sig);
    }

    /**
     * Register a gzip-bomb release: a tarball whose decompressed size is $decompressedBytes (highly
     * compressible zeros, so the .gz stays tiny) with a FORGED-SMALL ISIZE trailer so the forgeable
     * trailer would wave it through — only the streaming byte counter catches it. Correctly signed +
     * hashed so it reaches extraction. Pair with RulesUpdater::setMaxExtractedBytesForTesting() to
     * keep the fixture fast (e.g. cap 512 KiB, bomb 2 MiB).
     *
     * @return array{version:string,decompressed:int}
     */
    public function publishBomb(ArrayFetcher $fetcher, string $version, int $seq, int $decompressedBytes): array
    {
        $stage = $this->workDir . '/bomb-' . (++$this->tarSeq);
        @mkdir($stage, 0755, true);
        file_put_contents($stage . '/big.bin', str_repeat("\0", $decompressedBytes));

        $tarPath = $this->workDir . '/bomb-' . $this->tarSeq . '.tar';
        @unlink($tarPath);
        @unlink($tarPath . '.gz');
        $phar = new PharData($tarPath);
        $phar->buildFromDirectory($stage);
        $phar->compress(Phar::GZ);
        unset($phar);
        $gz = (string) file_get_contents($tarPath . '.gz');
        @unlink($tarPath);
        @unlink($tarPath . '.gz');
        @unlink($stage . '/big.bin');
        @rmdir($stage);

        // Forge the ISIZE trailer (last 4 bytes) to a small value — the whole point of the bomb test.
        $gz = substr($gz, 0, -4) . pack('V', 1024);

        $now = time();
        $manifest = [
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'version' => $version,
            'version_seq' => $seq,
            'generated_at' => gmdate('c', $now),
            'expires' => gmdate('c', $now + 90 * 86400),
            'key_id' => 'test-release',
            'tarball' => 'funnypot-rules-' . $version . '.tar.gz',
            'tarball_sha256' => hash('sha256', $gz),
            'files' => ['engine/big.bin' => hash('sha256', str_repeat("\0", $decompressedBytes))],
        ];
        $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $sig = $this->sign(SignatureVerifier::CONTEXT_MANIFEST, $manifestBytes, 'release');

        $base = $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/';
        $fetcher->put($base . $version . '.manifest.json', $manifestBytes);
        $fetcher->put($base . $version . '.manifest.json.sig', $sig);
        $fetcher->put($base . 'funnypot-rules-' . $version . '.tar.gz', $gz);

        return ['version' => $version, 'decompressed' => $decompressedBytes];
    }

    /**
     * Register a release whose tarball is a TRUNCATED gzip stream (the sha256 matches the truncated
     * bytes, so it passes the digest gate and reaches extraction, where the inflate stream ends
     * before its trailer). Fresh, correctly signed schema-2 manifest otherwise.
     */
    public function publishTruncatedGzip(ArrayFetcher $fetcher, string $version, int $seq, array $engineFiles): void
    {
        $full = $this->buildTarball($engineFiles);
        // Drop the trailing bytes (incl. the gzip CRC32 + ISIZE trailer) so the stream never finishes.
        $truncated = substr($full, 0, max(1, (int) (strlen($full) * 0.6)));

        $now = time();
        $manifest = [
            'schema' => SchemaVersion::RELEASE_CURRENT,
            'version' => $version,
            'version_seq' => $seq,
            'generated_at' => gmdate('c', $now),
            'expires' => gmdate('c', $now + 90 * 86400),
            'key_id' => 'test-release',
            'tarball' => 'funnypot-rules-' . $version . '.tar.gz',
            'tarball_sha256' => hash('sha256', $truncated),
            'files' => ['engine/funnypot-attack.php' => 'ignored'],
        ];
        $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $sig = $this->sign(SignatureVerifier::CONTEXT_MANIFEST, $manifestBytes, 'release');

        $base = $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/';
        $fetcher->put($base . $version . '.manifest.json', $manifestBytes);
        $fetcher->put($base . $version . '.manifest.json.sig', $sig);
        $fetcher->put($base . 'funnypot-rules-' . $version . '.tar.gz', $truncated);
    }

    /** Overwrite an already-published asset with tampered bytes (leaving the signature stale). */
    public function tamper(ArrayFetcher $fetcher, string $version, string $asset, string $bytes): void
    {
        $fetcher->put($this->baseUrl . '/releases/download/' . rawurlencode($version) . '/' . $asset, $bytes);
    }

    /** Raw access to the channels URL for hand-built cross-context/replay tests. */
    public function channelsUrl(string $asset): string
    {
        return $this->baseUrl . '/releases/download/channels/' . $asset;
    }

    /** Raw access to a version asset URL for hand-built cross-context/replay tests. */
    public function assetUrl(string $version, string $asset): string
    {
        return $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/' . $asset;
    }

    /** Detached signature over `$context . $bytes` with the chosen role's secret key. */
    public function sign(string $context, string $bytes, string $role): string
    {
        $secret = $role === 'channels' ? $this->channelsSecret : $this->releaseSecret;

        return sodium_crypto_sign_detached($context . $bytes, $secret);
    }

    /**
     * A minimal, valid engine artifact set. Pass counts to shape coverage; pass $attackRules to
     * inject custom attack rules (for fingerprint/ReDoS negative tests).
     *
     * @param array<int,array<string,mixed>>|null $attackRules
     * @return array<string,string>
     */
    public function engineFiles(int $routes = 100, int $templates = 100, ?array $attackRules = null): array
    {
        $routeMap = [];
        for ($i = 0; $i < $routes; $i++) {
            $routeMap['GET /r' . $i] = ['b' => [['pid' => 'p' . $i, 't' => ['t' . $i]]]];
        }
        $templateMap = [];
        for ($i = 0; $i < $templates; $i++) {
            $templateMap['t' . $i] = ['sev' => 'medium', 'tags' => ['x'], 'name' => 'T' . $i];
        }
        $index = ['schema' => 1, 'manifest' => ['schema' => 1], 'routes' => $routeMap, 'templates' => $templateMap];

        $attackRules = $attackRules ?? [[
            'id' => 'attack-demo',
            'severity' => 'high',
            'tags' => ['attack'],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'q=([a-z0-9]+)']],
            'response' => ['body' => 'ok'],
        ]];

        return [
            'nuclei-index.full.php' => $this->literal($index),
            'funnypot-attack.php' => $this->literal($attackRules),
            'funnypot-routes.php' => $this->literal([]),
            'funnypot-routes-index.php' => $this->literal(['routes' => [], 'templates' => []]),
            'funnypot-param.php' => $this->literal(['schema' => 1, 'buckets' => []]),
        ];
    }

    /** @param mixed $value */
    public function literal($value): string
    {
        return "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($value, true) . ";\n";
    }

    /** @param array<string,string> $engineFiles */
    private function buildTarball(array $engineFiles): string
    {
        $stage = $this->workDir . '/stage-' . (++$this->tarSeq);
        @mkdir($stage . '/engine', 0755, true);
        foreach ($engineFiles as $name => $contents) {
            file_put_contents($stage . '/engine/' . $name, $contents);
        }

        $tarPath = $this->workDir . '/rel-' . $this->tarSeq . '.tar';
        @unlink($tarPath);
        @unlink($tarPath . '.gz');
        $phar = new PharData($tarPath);
        $phar->buildFromDirectory($stage);
        $phar->compress(Phar::GZ);
        unset($phar);

        $bytes = (string) file_get_contents($tarPath . '.gz');
        // Clean up so PharData doesn't hold the file open across many fixtures.
        @unlink($tarPath);
        @unlink($tarPath . '.gz');

        return $bytes;
    }
}
