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
 * FP-0403 (Parts 1-4): JavaScript source-map canary lure. Two Astro source-map keys (CVE-2024-56159,
 * previously a degenerate invalid-JSON stub) are enriched, and six webpack/vite .js.map paths are new_page'd,
 * each serving a valid Source Map v3 whose sourcesContent reconstructs frontend TS files seeded with the
 * deploy-stable canary catalog (AWS/Stripe/OpenAI/JWT = the same creds /.env + /secrets.json leak). A recon
 * tool (sourcemapper/jsluice) scrapes the secrets and chases dead canaries. Part 5 (exfil tracking) → app.
 * Fixture: full compiled corpus via Honeypot::respond().
 */
final class SourceMapCanaryDecoyTest extends TestCase
{
    private const PATHS = [
        '/index.astro.mjs.map', '/pages/index.astro.mjs.map',
        '/static/js/main.js.map', '/assets/index.js.map', '/js/app.js.map',
        '/bundle.js.map', '/main.js.map', '/js/app.bundle.js.map',
    ];

    /** @var array<string,mixed>|null */
    private static $idx;

    /** @var array<string,Honeypot> per-seed engine cache (heap-churn lesson). */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_every_path_serves_valid_sourcemap_v3(): void
    {
        foreach (self::PATHS as $p) {
            $r = $this->resp($p);
            self::assertSame(200, $r->status ?? null, "{$p} must serve 200");
            self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''), "{$p} CT");
            $j = json_decode($this->body($r), true);
            self::assertIsArray($j, "{$p} must be valid JSON: {$this->body($r)}");
            self::assertSame(3, $j['version'] ?? null, "{$p} must be Source Map v3");
            self::assertArrayHasKey('sourcesContent', $j, "{$p} must carry sourcesContent");
        }
    }

    public function test_sourcescontent_embeds_the_canary_catalog(): void
    {
        foreach (self::PATHS as $p) {
            $j = json_decode($this->body($this->resp($p)), true);
            $sc = implode("\n", (array) ($j['sourcesContent'] ?? []));
            self::assertSame(1, preg_match('/AKIA[A-Z0-9]{12,}/', $sc), "{$p} must leak an AWS access key");
            self::assertStringContainsString('sk_live_', $sc, "{$p} must leak a Stripe key");
            self::assertStringContainsString('JWT_SECRET', $sc, "{$p} must leak the JWT secret");
        }
    }

    public function test_recon_extraction_matches_persona_canary(): void
    {
        // A recon tool reads sourcesContent; the extracted AWS key must equal the deploy's persona canary
        // (one credential story shared with /.env), not a per-request fake.
        $seed = 'hostZ';
        $ps = PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial($seed));
        $expect = (string) $ps->field('cloud.aws.accessKeyId');
        $j = json_decode($this->body($this->resp('/main.js.map', $seed)), true);
        $sc = implode("\n", (array) ($j['sourcesContent'] ?? []));
        self::assertStringContainsString($expect, $sc, 'the leaked AWS key must be the persona canary');
    }

    public function test_coherent_with_env_and_across_assets(): void
    {
        // The AWS key in the source map equals the one /.env leaks, and all map paths agree per deploy.
        $env = $this->body($this->resp('/.env', 'depA'));
        self::assertSame(1, preg_match('/AKIA[A-Z0-9]+/', $env, $e), '/.env must leak an AWS key');
        foreach (['/main.js.map', '/index.astro.mjs.map'] as $p) {
            self::assertStringContainsString($e[0], $this->body($this->resp($p, 'depA')), "{$p} must share the /.env AWS key");
        }
    }

    public function test_deploy_stable_and_varies(): void
    {
        self::assertSame($this->body($this->resp('/main.js.map', 'depA')), $this->body($this->resp('/main.js.map', 'depA')), 'stable per deploy');
        self::assertNotSame($this->body($this->resp('/main.js.map', 'depA')), $this->body($this->resp('/main.js.map', 'depB')), 'varies across deploys');
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 400; $s++) {
            foreach (['/main.js.map', '/index.astro.mjs.map'] as $p) {
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $this->body($this->resp($p, (string) $s))), "seed {$s} {$p} denylist run");
            }
        }
    }

    public function test_no_reflection(): void
    {
        $b = $this->body($this->engine()->respond(new RequestContext('GET', '/main.js.map', 'x=ZZCANARYZZ', [], null, 'x.test')));
        self::assertStringNotContainsString('ZZCANARYZZ', $b, 'no request byte may be reflected');
    }
}
