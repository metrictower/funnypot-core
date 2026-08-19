<?php

declare(strict_types=1);

namespace Funnypot\Tests\Support;

use Funnypot\Rules\KeyRing;
use Funnypot\Rules\SignatureVerifier;
use Phar;
use PharData;

/**
 * Builds signed funnypot-rules release fixtures for the updater tests: a gzipped tarball of
 * engine artifacts, a manifest that pins their sha256s, and a detached ed25519 signature over
 * the manifest — all served through an ArrayFetcher at the exact URLs RulesUpdater requests.
 * Owns a throwaway ed25519 keypair whose public half is the only trusted signer.
 */
final class ReleaseFactory
{
    public string $baseUrl = 'https://github.com/metrictower/funnypot-rules';
    private string $secretKey;
    private string $publicKey;
    private string $workDir;
    private int $tarSeq = 0;

    public function __construct(string $workDir)
    {
        $pair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($pair);
        $this->publicKey = sodium_crypto_sign_publickey($pair);
        $this->workDir = rtrim($workDir, '/');
        @mkdir($this->workDir, 0755, true);
    }

    /** A verifier that trusts exactly this factory's key. */
    public function verifier(): SignatureVerifier
    {
        return new SignatureVerifier($this->keyRing());
    }

    public function keyRing(): KeyRing
    {
        return new KeyRing([[
            'key_id' => 'test-2026',
            'public_key' => base64_encode($this->publicKey),
            'valid_from' => '2000-01-01',
            'valid_until' => null,
        ]]);
    }

    /**
     * Register a full release (manifest + sig + tarball) with $fetcher under $version.
     *
     * @param array<string,string> $engineFiles artifactName => PHP file contents
     * @param array<string,mixed>  $manifestOverrides tweak/replace manifest fields for negative tests
     * @return array{version:string,tarball:string,manifest:array<string,mixed>,tarball_bytes:string}
     */
    public function publish(ArrayFetcher $fetcher, string $version, int $seq, array $engineFiles, array $manifestOverrides = []): array
    {
        $tarballName = 'funnypot-rules-' . $version . '.tar.gz';
        $tarballBytes = $this->buildTarball($engineFiles);

        $files = [];
        foreach ($engineFiles as $name => $contents) {
            $files['engine/' . $name] = hash('sha256', $contents);
        }

        $manifest = array_merge([
            'schema' => 1,
            'version' => $version,
            'version_seq' => $seq,
            'built_at' => gmdate('c'),
            'key_id' => 'test-2026',
            'tarball' => $tarballName,
            'tarball_sha256' => hash('sha256', $tarballBytes),
            'files' => $files,
        ], $manifestOverrides);

        $manifestBytes = json_encode($manifest, JSON_UNESCAPED_SLASHES);
        $sig = sodium_crypto_sign_detached($manifestBytes, $this->secretKey);

        $base = $this->baseUrl . '/releases/download/' . rawurlencode($version) . '/';
        $fetcher->put($base . $version . '.manifest.json', $manifestBytes);
        $fetcher->put($base . $version . '.manifest.json.sig', $sig);
        $fetcher->put($base . $tarballName, $tarballBytes);

        return ['version' => $version, 'tarball' => $tarballName, 'manifest' => $manifest, 'tarball_bytes' => $tarballBytes];
    }

    /** Register a signed channels.json mapping channel => version. */
    public function publishChannels(ArrayFetcher $fetcher, array $channels): void
    {
        $bytes = json_encode($channels, JSON_UNESCAPED_SLASHES);
        $sig = sodium_crypto_sign_detached($bytes, $this->secretKey);
        $base = $this->baseUrl . '/releases/download/channels/';
        $fetcher->put($base . 'channels.json', $bytes);
        $fetcher->put($base . 'channels.json.sig', $sig);
    }

    /** Overwrite an already-published asset with tampered bytes (leaving the signature stale). */
    public function tamper(ArrayFetcher $fetcher, string $version, string $asset, string $bytes): void
    {
        $fetcher->put($this->baseUrl . '/releases/download/' . rawurlencode($version) . '/' . $asset, $bytes);
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
