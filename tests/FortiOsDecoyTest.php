<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0409: the FortiOS SSL-VPN login/fingerprint surface (/remote/login, /fpc/app/login) for the
 * CVE-2024-55591 band. Core serves only the stateless HTTP login page; the WebSocket auth-bypass + CLI
 * capture is the app follow-up (FP-0540). Distinct from 80-fortios (CVE-2022-40684).
 */
final class FortiOsDecoyTest extends TestCase
{
    private const AFFECTED = '/^7\.0\.(\d|1[0-6])$/'; // FortiOS 7.0.0-7.0.16 (CVE-2024-55591; 7.2.x NOT affected)

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

    private function engine(string $seed = 'fixed', string $ceiling = 'high'): Honeypot
    {
        // Default ceiling 'high' — the surfaces must serve for the wordpress/laravel embedders, not only prod.
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling,
            65536, 0, 0, false, null, null, null, $seed);

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    private function resp(string $path, string $query = '', string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_both_login_paths_serve_the_fortios_fingerprint(): void
    {
        foreach (['/remote/login', '/fpc/app/login'] as $p) {
            $r = $this->resp($p);
            self::assertSame(200, $r->status ?? null, "{$p} must serve");
            $b = $this->body($r);
            self::assertStringContainsString('class="main-app"', $b, "{$p}: FortiOS GUI root class");
            self::assertStringContainsString('<f-icon', $b, "{$p}: FortiOS f-icon web component");
            self::assertStringContainsString('action="/remote/logincheck"', $b, "{$p}: FortiOS login form target");
        }
    }

    public function test_apscookie_header_is_present_and_hex_shaped(): void
    {
        $ck = $this->resp('/remote/login')->headers['Set-Cookie'] ?? '';
        self::assertSame(1, preg_match('/^APSCOOKIE_[a-f0-9]{10}="[a-f0-9]{40}"; path=\/; secure; httponly/', (string) $ck),
            "APSCOOKIE must be a hex-shaped session cookie, got: {$ck}");
    }

    public function test_version_is_on_the_affected_side_and_coherent_across_surfaces(): void
    {
        // Cross-surface coherence: both FortiOS pages on ONE deploy render the SAME version (that is the
        // whole reason a persona field was chosen over a per-request {{pick}}). Compare the two rendered
        // pages directly rather than a separately-seeded field value.
        $a = $this->renderedVersion($this->body($this->resp('/remote/login', '', 'hostA')));
        $b = $this->renderedVersion($this->body($this->resp('/fpc/app/login', '', 'hostA')));
        self::assertSame($a, $b, 'both FortiOS surfaces must show the same version for one deploy');
        self::assertSame(1, preg_match(self::AFFECTED, $a), "version must be on the CVE-2024-55591 affected side: {$a}");
    }

    public function test_every_pool_version_is_in_the_affected_band(): void
    {
        for ($s = 0; $s < 2000; $s++) {
            $v = (string) PersonaIdentity::fromSeed($s)->field('fortios.version');
            self::assertSame(1, preg_match(self::AFFECTED, $v), "seed {$s}: fortios.version must be FortiOS 7.0.0-7.0.16, got {$v}");
        }
    }

    private function renderedVersion(string $body): string
    {
        self::assertSame(1, preg_match('/v(7\.[0-9.]+)</', $body, $m), 'a FortiOS version must render in the page');

        return $m[1];
    }

    public function test_version_varies_per_deploy(): void
    {
        $versions = [];
        foreach (['s1', 's2', 's3', 's4', 's5', 's6'] as $s) {
            $versions[(string) PersonaIdentity::fromSeed(crc32($s))->field('fortios.version')] = 1;
        }
        self::assertGreaterThan(1, count($versions), 'fortios.version must vary across deploys (anti-fingerprint)');
    }

    public function test_query_and_trailing_slash_variants_resolve(): void
    {
        self::assertSame(200, $this->resp('/remote/login', 'lang=en')->status ?? null);
        self::assertSame(200, $this->resp('/remote/login/')->status ?? null);
    }

    public function test_cve_2022_40684_decoy_stays_intact(): void
    {
        // 80-fortios (attack-fortios-40684) is severity: critical, so it serves only at a critical ceiling
        // (unchanged by FP-0409). The Forwarded-header admin-API bypass must still answer super_admin.
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->attackEmulation = true;
        $h = new Honeypot(new PhpArrayStore(self::index()), $cfg);
        $r = $h->respond(new RequestContext('GET', '/api/v2/cmdb/system/admin', '',
            ['Forwarded' => 'for="[127.0.0.1]:8000"'], null, 'x.test'));
        self::assertStringContainsString('super_admin', $this->body($r));
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        // APSCOOKIE (hex) + version (dotted) must never form the denylist's bare 6-digit run.
        for ($s = 0; $s < 1500; $s++) {
            $r = $this->resp('/remote/login', '', (string) $s);
            $hay = $this->body($r) . ' ' . (string) ($r->headers['Set-Cookie'] ?? '');
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $hay), "seed {$s} formed a denylisted run");
        }
    }
}
