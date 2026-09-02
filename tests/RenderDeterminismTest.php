<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * The determinism contract (FP-0276): within a deploy, re-scans are byte-identical modulo the
 * §1.4 legitimate per-request exceptions; across deploys, seeded surfaces differ. This exercises the
 * FULL respond() facade (where E1 X-Request-Id appears) and RouteTemplateEmulator directly (where E2
 * the per-request Set-Cookie appears), masking exactly those two, and documents E3 (volatileProof)
 * as intended non-determinism. The seeded-render CI gate is the corpus-wide backstop; this pins the
 * facade layer and the exception list the gate renders below.
 */
final class RenderDeterminismTest extends TestCase
{
    private function inverter(string $deploySeed = 'id-secret', bool $volatileProof = false): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'high',
            65536,
            0,
            0,      // jitter 0
            true    // attackEmulation
        );
        $config->seedSalt = 'render-salt';
        $config->deploySeed = $deploySeed;
        $config->isolatedOrigin = true;
        $config->volatileProof = $volatileProof;

        return new Honeypot($store, $config);
    }

    /**
     * A canonical tuple with the two legitimate per-request variances masked: E1 X-Request-Id dropped,
     * E2 Set-Cookie random value masked to its shape (and the shape asserted).
     *
     * @return array{status:int,headers:array<string,string>,body:string}
     */
    private function canon(SynthesizedResponse $r): array
    {
        $headers = [];
        foreach ($r->headers as $name => $value) {
            $value = is_array($value) ? implode("\x00", $value) : (string) $value;
            if (strcasecmp((string) $name, 'X-Request-Id') === 0) {
                self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $value, 'E1 X-Request-Id shape');
                continue;
            }
            if (strcasecmp((string) $name, 'Set-Cookie') === 0) {
                $value = (string) preg_replace('/^([^=]+)=[0-9a-f]{32}(; path=\/; HttpOnly)$/', '$1=<rand>$2', $value);
            }
            $headers[(string) $name] = $value;
        }
        ksort($headers);

        return ['status' => $r->status, 'headers' => $headers, 'body' => $r->body];
    }

    public function test_facade_respond_is_byte_identical_on_rescan_modulo_x_request_id(): void
    {
        $h = $this->inverter();
        foreach ([['GET', '/wp/xmlrpc.php', 'rsd'], ['GET', '/.env', ''], ['GET', '/config.json', '']] as $probe) {
            $r1 = $h->respond(new RequestContext($probe[0], $probe[1], $probe[2], [], null, 'vic.example'));
            $r2 = $h->respond(new RequestContext($probe[0], $probe[1], $probe[2], [], null, 'vic.example'));
            self::assertNotNull($r1, "{$probe[1]} should serve");
            self::assertNotNull($r2);
            self::assertSame($this->canon($r1), $this->canon($r2), "re-scan of {$probe[1]} must be byte-identical (X-Request-Id masked)");
        }
    }

    public function test_route_set_cookie_is_deterministic_after_masking_its_random_value(): void
    {
        // The 11 set_cookie route rules mint a fresh 32-hex cookie value per request (E2). After masking
        // that value to its shape, the two renders at one deploy are byte-identical.
        $routes = require __DIR__ . '/../resources/compiled/funnypot-routes.php';
        $set = new RouteTemplateSet($routes);
        $rule = null;
        foreach ($routes as $r) {
            if (($r['id'] ?? '') === 'route-wp-login') {
                $rule = $r;
                break;
            }
        }
        self::assertNotNull($rule, 'route-wp-login must exist');
        $emu = new RouteTemplateEmulator($set, new \Funnypot\Core\Template\DirectiveRenderer(999));
        $bundle = ['pid' => $rule['match']['template_needle'][0] ?? '', 't' => [$rule['match']['template_needle'][0] ?? ''], 'bw' => []];
        $c1 = $emu->render($bundle, Style::REALISTIC, 4242);
        $c2 = $emu->render($bundle, Style::REALISTIC, 4242);
        self::assertNotNull($c1);
        self::assertNotNull($c2);
        // Raw values differ (fresh random), masked values match.
        self::assertNotSame($c1->headers['Set-Cookie'], $c2->headers['Set-Cookie'], 'the cookie value is fresh per request');
        self::assertMatchesRegularExpression('/^PHPSESSID=[0-9a-f]{32}; path=\/; HttpOnly$/', $c1->headers['Set-Cookie'], 'E2 shape');
        $mask = static function (string $v): string {
            return (string) preg_replace('/=[0-9a-f]{32};/', '=<rand>;', $v);
        };
        self::assertSame($mask($c1->headers['Set-Cookie']), $mask($c2->headers['Set-Cookie']));
        self::assertSame($c1->body, $c2->body, 'the body is deterministic');
    }

    public function test_volatile_proof_arm_mints_a_fresh_token_per_request(): void
    {
        // E3, documented as intended: with volatileProof on, an armed proof body is non-reproducible.
        $h = $this->inverter('id-secret', true);
        $probe = new RequestContext('GET', '/api/items', 'offset=0x41', [], null, 'vic.example');
        $r1 = $h->respond($probe);
        $r2 = $h->respond($probe);
        if ($r1 === null || $r2 === null) {
            self::markTestSkipped('volatile probe not reachable in this store');
        }
        self::assertNotSame($r1->body, $r2->body, 'a {{volatile.*}} body must NOT reproduce under the armed arm (E3)');
    }

    public function test_cross_deploy_persona_surface_differs(): void
    {
        $a = $this->inverter('deploy-a');
        $b = $this->inverter('deploy-b');
        $probe = new RequestContext('GET', '/wp/xmlrpc.php', 'rsd', [], null, 'vic.example');
        $ra = $a->respond($probe);
        $rb = $b->respond($probe);
        self::assertNotNull($ra);
        self::assertNotNull($rb);
        self::assertNotSame($ra->body, $rb->body, 'the persona-bearing RSD surface must differ across deploy seeds');
    }

    /**
     * A Honeypot over the FULL index (the surface-graph new_page bundles live there, not in the
     * trimmed nuclei-index.php the probes above use).
     */
    private function fullInverter(string $deploySeed): Honeypot
    {
        ini_set('memory_limit', '512M');
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'high',
            65536,
            0,
            0,
            true
        );
        $config->seedSalt = 'render-salt';
        $config->deploySeed = $deploySeed;
        $config->isolatedOrigin = true;

        return new Honeypot($store, $config);
    }

    public function test_facade_surface_graph_is_byte_identical_on_rescan(): void
    {
        // FP-0278: the deploy-seeded surface graph is a pure function of the deploy seed, so a re-scan
        // within one deploy is byte-identical (X-Request-Id masked); these routes set no cookie.
        $h = $this->fullInverter('id-secret');
        foreach (['/sitemap.xml', '/robots.txt', '/api', '/openapi.json'] as $path) {
            $r1 = $h->respond(new RequestContext('GET', $path, '', [], null, 'vic.example'));
            $r2 = $h->respond(new RequestContext('GET', $path, '', [], null, 'vic.example'));
            self::assertNotNull($r1, "{$path} should serve");
            self::assertNotNull($r2);
            self::assertSame($this->canon($r1), $this->canon($r2), "re-scan of {$path} must be byte-identical (X-Request-Id masked)");
        }
    }

    public function test_facade_surface_graph_differs_across_deploys(): void
    {
        // Across deploys the seeded set/order/nouns differ. robots is excluded: its 96-variant axis can
        // collide on a specific pair (the sitemap carries the entropy) — the sweep in
        // SurfaceGraphRoutingTest proves the robots axis is live.
        $a = $this->fullInverter('deploy-a');
        $b = $this->fullInverter('deploy-b');
        foreach (['/sitemap.xml', '/api', '/openapi.json'] as $path) {
            $ra = $a->respond(new RequestContext('GET', $path, '', [], null, 'vic.example'));
            $rb = $b->respond(new RequestContext('GET', $path, '', [], null, 'vic.example'));
            self::assertNotNull($ra, "{$path} should serve on deploy-a");
            self::assertNotNull($rb, "{$path} should serve on deploy-b");
            self::assertNotSame($ra->body, $rb->body, "the seeded surface {$path} must differ across deploy seeds");
        }
    }

    /**
     * A Honeypot over a controlled in-test index whose one route falls to MINIMAL synthesis (no route
     * template recognises its marker) — so the FP-0281 deploy-seeded scaffold order is what the facade
     * serves. Mirrors inverter()'s config, with the store swapped.
     */
    private function minimalSynthInverter(string $deploySeed): Honeypot
    {
        $index = [
            'schema' => 1,
            'templates' => ['fp-0281-marker' => ['sev' => 'medium', 'tags' => ['exposure'], 'name' => 'FP-0281 minimal synth probe']],
            'routes' => ['GET /fp-0281' => ['b' => [[
                's' => 200,
                'bw' => ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'],
                'h' => ['Content-Type' => 'text/plain'],
                'pid' => 'fp-0281',
                'sev' => 'medium',
                'sig' => 0,
                't' => ['fp-0281-marker'],
            ]]]],
        ];
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'high',
            65536,
            0,
            0,
            true
        );
        $config->seedSalt = 'render-salt';
        $config->deploySeed = $deploySeed;
        $config->isolatedOrigin = true;

        return new Honeypot(new PhpArrayStore($index), $config);
    }

    public function test_minimal_synth_body_is_byte_identical_on_rescan_within_a_deploy(): void
    {
        // Within one deploy the seeded word order is a pure function of the deploy seed, so re-scans are
        // byte-identical (X-Request-Id masked). Proves E1 is still the only per-request byte on the
        // minimal path.
        $h = $this->minimalSynthInverter('id-secret');
        $probe = new RequestContext('GET', '/fp-0281', '', [], null, 'vic.example');
        $r1 = $h->respond($probe);
        $r2 = $h->respond($probe);
        self::assertNotNull($r1, '/fp-0281 should serve via minimal synthesis');
        self::assertNotNull($r2);
        self::assertSame($this->canon($r1), $this->canon($r2), 're-scan must be byte-identical (X-Request-Id masked)');
        // The served body is exactly the deploy-seeded order of the words (arm is not vacuous — S1).
        $seed = \Funnypot\Core\Support\PersonaIdentity::seedFromMaterial('id-secret');
        $expected = implode("\n", \Funnypot\Core\Synthesis\SynthScaffold::bodyOrder(['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'], $seed));
        self::assertSame($expected, $r1->body, 'the served body is the deploy-seeded word order');
    }

    public function test_minimal_synth_body_order_differs_across_deploys(): void
    {
        $probe = new RequestContext('GET', '/fp-0281', '', [], null, 'vic.example');
        $ra = $this->minimalSynthInverter('deploy-a')->respond($probe);
        $rb = $this->minimalSynthInverter('deploy-b')->respond($probe);
        self::assertNotNull($ra, '/fp-0281 should serve on deploy-a');
        self::assertNotNull($rb, '/fp-0281 should serve on deploy-b');
        self::assertNotSame($ra->body, $rb->body, 'the seeded minimal-synth word order must differ across deploys');
        // Same bytes, only reordered — no invented content.
        $la = explode("\n", $ra->body);
        $lb = explode("\n", $rb->body);
        sort($la);
        sort($lb);
        self::assertSame($la, $lb, 'the word multiset is deploy-invariant (permutation only)');
    }

    public function test_the_canonicalization_is_not_vacuous(): void
    {
        // A negative control: two responses differing only in body are NOT equal after masking, so the
        // harness would catch a body that varied per request.
        $a = new SynthesizedResponse(200, ['X-Request-Id' => 'aaaaaaaaaaaaaaaa'], 'body-one', \Funnypot\Core\Detection::none());
        $b = new SynthesizedResponse(200, ['X-Request-Id' => 'bbbbbbbbbbbbbbbb'], 'body-two', \Funnypot\Core\Detection::none());
        self::assertNotSame($this->canon($a), $this->canon($b));
        // But two differing ONLY in X-Request-Id are equal after masking.
        $c = new SynthesizedResponse(200, ['X-Request-Id' => 'cccccccccccccccc'], 'body-one', \Funnypot\Core\Detection::none());
        self::assertSame($this->canon($a), $this->canon($c));
    }
}
