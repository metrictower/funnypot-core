<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0399: vulnerable lockfile decoys. Eight enrich documents dress the corpus lockfile route keys
 * (/package-lock.json, /package.json, /yarn.lock, /composer.lock, /composer.json, /requirements.txt,
 * /Pipfile.lock, /Pipfile) with REAL OSV-listed vulnerable package name+version pairs, so an SCA scanner
 * that scrapes them parses (ecosystem, name, version) and reports verifiable CVEs. Versions are fixed
 * literals (the detection payload); hash/integrity fields are seeded. Inert, no request reflected.
 */
final class VulnerableLockfileDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $indexCache;

    /** @var array<string,mixed> */
    private static function index(): array
    {
        if (self::$indexCache === null) {
            self::$indexCache = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$indexCache;
    }

    private function engine(string $seed = 'fixed'): Honeypot
    {
        // Lockfile bundles are info/low, so they serve at every ceiling; pin 'high' (the embedder default).
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high',
            65536, 0, 0, false, null, null, null, $seed);

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    /** @return array<string,array{0:string,1:string[],2:bool,3:string}> path => [markers, isJson, contentType] */
    private static function surfaces(): array
    {
        return [
            '/package-lock.json' => [['"lockfileVersion": 3', '"version": "4.17.11"', '"version": "0.21.1"'], true, 'application/json'],
            '/package.json'      => [['"express": "4.16.4"', '"lodash": "4.17.11"'], true, 'application/json'],
            '/yarn.lock'         => [['# yarn lockfile v1', 'version "4.17.11"'], false, 'text/html'],
            '/composer.lock'     => [['"facade/ignition"', '"version": "2.5.1"', '"phpunit/phpunit"', '"version": "5.6.2"'], true, 'application/octet-stream'],
            '/composer.json'     => [['laravel/framework', 'getcomposer.org', 'packages'], true, 'application/octet-stream'],
            '/requirements.txt'  => [['Django==3.0.4', 'PyYAML==5.1', 'urllib3==1.25.7'], false, 'text/plain'],
            '/Pipfile.lock'      => [['"pipfile-spec": 6', '"version": "==3.0.4"'], true, 'application/json'],
            '/Pipfile'           => [['[[source]]', '[packages]', 'django = "==3.0.4"'], false, 'text/plain'],
        ];
    }

    public function test_every_lockfile_serves_its_vulnerable_set(): void
    {
        foreach (self::surfaces() as $path => [$markers, $isJson, $ct]) {
            $r = $this->resp($path);
            self::assertSame(200, $r->status ?? null, "{$path} must serve");
            $b = $this->body($r);
            foreach ($markers as $m) {
                self::assertStringContainsString($m, $b, "{$path} must carry {$m}");
            }
            if ($isJson) {
                self::assertNotNull(json_decode($b), "{$path} must be valid JSON even with the taunt field: {$b}");
            }
            self::assertStringContainsString(explode('|', $ct)[0], (string) ($r->headers['Content-Type'] ?? ''), "{$path} Content-Type");
        }
    }

    public function test_package_lock_guard_wins_over_the_manifest(): void
    {
        // /package-lock.json (81, route_key-guarded) must serve the LOCK, not the /package.json manifest.
        $lock = $this->body($this->resp('/package-lock.json'));
        self::assertStringContainsString('"lockfileVersion": 3', $lock);
        self::assertStringContainsString('"node_modules/lodash"', $lock);
    }

    public function test_composer_lock_guard_wins_over_the_manifest(): void
    {
        $lock = $this->body($this->resp('/composer.lock'));
        self::assertStringContainsString('"content-hash"', $lock);
        self::assertStringContainsString('"packages-dev"', $lock);
    }

    public function test_emulator_coherent_php_cves_present(): void
    {
        // facade/ignition 2.5.1 (CVE-2021-3129) + phpunit 5.6.2 (CVE-2017-9841) match the box's own
        // Ignition (92) and PHPUnit (15) attack emulators.
        $b = $this->body($this->resp('/composer.lock'));
        self::assertStringContainsString('"facade/ignition"', $b);
        self::assertStringContainsString('"version": "2.5.1"', $b);
        self::assertStringContainsString('"phpunit/phpunit"', $b);
        self::assertStringContainsString('"version": "5.6.2"', $b);
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        // Seeded integrity/hash/reference fields must never form the denylist's bare 6-digit run.
        $paths = ['/package-lock.json', '/yarn.lock', '/composer.lock', '/Pipfile.lock'];
        for ($s = 0; $s < 1200; $s++) {
            foreach ($paths as $p) {
                $b = $this->body($this->resp($p, (string) $s));
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} {$p} formed a denylisted run");
            }
        }
    }

    public function test_versions_are_deterministic_but_hashes_vary_per_seed(): void
    {
        // Versions are fixed (detection payload); the seeded hash fields differ across deploys (anti-correlation).
        $a = $this->body($this->resp('/package-lock.json', 'seedA'));
        $b = $this->body($this->resp('/package-lock.json', 'seedB'));
        self::assertStringContainsString('"version": "4.17.11"', $a);
        self::assertStringContainsString('"version": "4.17.11"', $b, 'the vulnerable version is fixed across deploys');
        self::assertNotSame($a, $b, 'seeded integrity fields must differ across deploys');
    }
}
