<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0420: framework debug-panel decoys — the Spring Cloud Gateway routes recon surface
 * (/actuator/gateway/routes + /gateway/routes) and the Clockwork profiler endpoints (/__clockwork,
 * /__clockwork/latest, /__clockwork/app). All five are corpus route keys previously answered only by
 * minimal synthesis (bare body words -> invalid JSON, and /__clockwork/app as text/plain). These enrich
 * templates dress each bundle with the real product's output; the JSON surfaces must parse and the app
 * shell must be text/html. Spring Actuator (env/health/heapdump/...) and Laravel Ignition were already
 * shipped (see NewPageRoutingTest) and are out of scope here.
 */
final class FrameworkDebugPanelDecoysTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high',
            65536, 0, 0, false, null, null, null, $seed);

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    /** @return array<string,array{0:string,1:bool,2:string,3:string[]}> path => [isJson, contentType, markers] */
    private static function surfaces(): array
    {
        return [
            '/actuator/gateway/routes' => [true, 'application/json', ['"route_id"', '"predicate"', 'admin-internal']],
            '/gateway/routes'          => [true, 'application/json', ['"route_id"', '"predicate"', 'admin-internal']],
            '/__clockwork'             => [true, 'application/json', ['"__meta":', '"toolbar":']],
            '/__clockwork/latest'      => [true, 'application/json', ['"id":', '"version":', '"method":', '"url":', '"time":', 'databaseQueries']],
            '/__clockwork/app'         => [false, 'text/html', ['<title>Clockwork</title>', '<div id="clockwork">']],
        ];
    }

    public function test_each_surface_serves_its_dressed_body(): void
    {
        foreach (self::surfaces() as $path => [$isJson, $ct, $markers]) {
            $r = $this->resp($path);
            self::assertSame(200, $r->status ?? null, "{$path} must serve 200");
            $b = $this->body($r);
            foreach ($markers as $m) {
                self::assertStringContainsString($m, $b, "{$path} must carry {$m}");
            }
            self::assertStringContainsString($ct, (string) ($r->headers['Content-Type'] ?? ''), "{$path} Content-Type");
            if ($isJson) {
                // Proves the enrich fired: bare body words (minimal synth) are not valid JSON.
                self::assertNotNull(json_decode($b), "{$path} must be valid JSON: {$b}");
            }
        }
    }

    public function test_gateway_needle_serves_both_keys(): void
    {
        // One shared bundle (needle springboot-gateway) dresses both keys — not a new_page per key.
        foreach (['/actuator/gateway/routes', '/gateway/routes'] as $p) {
            $b = $this->body($this->resp($p));
            self::assertStringContainsString('"route_id"', $b, "{$p} must serve the gateway route list");
            self::assertStringContainsString('lb://', $b, "{$p} must carry a persona-coherent lb:// uri");
        }
    }

    public function test_clockwork_app_is_html_not_text_plain(): void
    {
        $r = $this->resp('/__clockwork/app');
        self::assertStringStartsWith('text/html', (string) ($r->headers['Content-Type'] ?? ''),
            '/__clockwork/app must be text/html (the minimal-synth text/plain is a tell)');
    }

    public function test_persona_coherent_across_surfaces(): void
    {
        // The Clockwork db connection must be the SAME persona db as /actuator/env, per deploy; and bodies
        // must differ across deploys.
        $latestA = $this->body($this->resp('/__clockwork/latest', 'hostA'));
        $envA = $this->body($this->resp('/actuator/env', 'hostA'));
        self::assertSame(1, preg_match('/"connection": "([^"]+)"/', $latestA, $m), 'latest must name a db connection');
        self::assertStringContainsString($m[1], $envA, 'Clockwork db connection must match /actuator/env (one persona)');

        $latestB = $this->body($this->resp('/__clockwork/latest', 'hostB'));
        self::assertNotSame($latestA, $latestB, 'bodies must differ across deploys');
    }

    public function test_byte_identical_per_seed(): void
    {
        foreach (array_keys(self::surfaces()) as $path) {
            self::assertSame($this->body($this->resp($path, 'seedZ')), $this->body($this->resp($path, 'seedZ')),
                "{$path} must be byte-identical for one seed");
        }
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        $paths = array_keys(self::surfaces());
        for ($s = 0; $s < 1200; $s++) {
            foreach ($paths as $p) {
                $b = $this->body($this->resp($p, (string) $s));
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} {$p} formed a denylisted run");
            }
        }
    }

    public function test_fingerprint_guard_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach (array_keys(self::surfaces()) as $p) {
            for ($s = 0; $s < 200; $s++) {
                $r = $this->resp($p, (string) $s);
                self::assertSame([], $guard->scanResponse($this->body($r), (array) ($r->headers ?? [])), "seed {$s} {$p} tripped FingerprintGuard");
            }
        }
    }

    public function test_already_shipped_surfaces_unregressed(): void
    {
        // The new needles must not shadow the already-shipped actuator / ignition / telescope routes.
        self::assertStringContainsString('spring.datasource.password', $this->body($this->resp('/actuator/env')));
        self::assertStringContainsString('can_execute_commands', $this->body($this->resp('/_ignition/health-check')));
        self::assertStringContainsString('<title>Telescope</title>', $this->body($this->resp('/telescope/requests')));
    }
}
