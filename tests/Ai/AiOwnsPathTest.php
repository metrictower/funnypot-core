<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Ai;

use Funnypot\Core\Ai\ModelCatalog;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The AI owns_path attack tier (compiled by `funnypot compile-ai` into templates/attack-ai/).
 *  - A4b: the three Ollama GET recon pages (/api/version, /api/tags, /api/ps) are CLAIMED via
 *    owns_path, so the AI fake wins deterministically instead of losing a persona-weight lottery.
 *  - A6:  /api/show reflects a known catalog model's full show payload; an unknown model is a 404
 *    that reflects the (quote-safe) captured name.
 * Bodies stay catalog-derived — ModelCatalog is the single source of truth.
 */
final class AiOwnsPathTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../../resources/compiled/funnypot-attack.php';
    private const INDEX = __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
    private const JSON_CT = 'application/json; charset=utf-8';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    private function catalog(): ModelCatalog
    {
        return ModelCatalog::fromPackage();
    }

    /** A full engine with the attack tier live, pinned to one persona seed — the owns_path override
     *  runs inside classify(), so this exercises the real serve path, not just the emulator. */
    private function engine(string $seed): Honeypot
    {
        $store = new PhpArrayStore(require self::INDEX);

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            true // attackEmulation ⇒ classify() runs the owns_path override tier
        ));
    }

    /** The three GET recon paths and the exact catalog body each must serve. */
    private function getRecon(): array
    {
        $cat = $this->catalog();

        return [
            '/api/version' => '{"version":"0.11.4"}',
            '/api/tags' => (string) json_encode($cat->ollamaTags(), JSON_UNESCAPED_SLASHES),
            '/api/ps' => (string) json_encode($cat->ollamaPs(), JSON_UNESCAPED_SLASHES),
        ];
    }

    public function test_get_recon_paths_are_owned_and_serve_the_catalog_body(): void
    {
        $em = $this->emulator();
        foreach ($this->getRecon() as $path => $body) {
            self::assertTrue($em->ownsPath($path), "{$path} must be claimed via owns_path");

            $r = $em->emulate(new RequestContext('GET', $path, '', [], ''));
            self::assertNotNull($r, "{$path} must serve");
            self::assertSame(200, $r->status, "{$path} status");
            self::assertSame(self::JSON_CT, $r->headers['Content-Type'] ?? null, "{$path} Content-Type");
            self::assertSame($body, $r->body, "{$path} body must be the catalog-derived bytes");
        }
    }

    /**
     * The whole point of A4b: with the path claimed via owns_path, the AI fake wins 100% of the time
     * — no persona-weight lottery. Sweep seeds 0..199 through the FULL engine and require every one
     * to serve the exact Ollama body (before owns_path, /api/version lost on ~1/2000 seeds).
     */
    public function test_get_recon_is_deterministic_across_a_seed_sweep(): void
    {
        foreach ($this->getRecon() as $path => $body) {
            $served = 0;
            for ($seed = 0; $seed <= 199; $seed++) {
                $resp = $this->engine((string) $seed)->respond(new RequestContext('GET', $path));
                if ($resp !== null
                    && $resp->body === $body
                    && ($resp->headers['Content-Type'] ?? null) === self::JSON_CT) {
                    $served++;
                }
            }
            self::assertSame(200, $served, "{$path} must serve the Ollama body on every one of 200 seeds");
        }
    }

    public function test_get_recon_declines_non_get_so_it_falls_through(): void
    {
        // owns_path claims the path, but a POST misses the GET-gated match — matchRule returns null,
        // so classify() falls back to the static route bundle (no owns_path lock-in on the wrong verb).
        foreach (array_keys($this->getRecon()) as $path) {
            self::assertNull(
                $this->emulator()->emulate(new RequestContext('POST', $path, '', [], '{}')),
                "{$path} POST must not match the GET recon rule"
            );
        }
    }

    // --- A6: /api/show -----------------------------------------------------------------------

    public function test_api_show_is_owned(): void
    {
        self::assertTrue($this->emulator()->ownsPath('/api/show'));
    }

    public function test_api_show_reflects_every_known_model(): void
    {
        $em = $this->emulator();
        $cat = $this->catalog();
        $guard = FingerprintGuard::fromPackage();

        foreach ($cat->all() as $entry) {
            $name = (string) $entry['name'];
            $r = $em->emulate(new RequestContext('POST', '/api/show', '', [], '{"model":"' . $name . '"}'));
            self::assertNotNull($r, "{$name} must serve");
            self::assertSame(200, $r->status, "{$name} status");
            self::assertSame(self::JSON_CT, $r->headers['Content-Type'] ?? null, "{$name} Content-Type");
            // Byte-identity to the catalog projection proves the escaped `{{ .Prompt }}` round-trips.
            self::assertSame(
                (string) json_encode($cat->ollamaShow($name), JSON_UNESCAPED_SLASHES),
                $r->body,
                "{$name} body must equal ollamaShow()"
            );
            self::assertSame(['attack-ai-ollama-show'], $r->satisfies->templateIds(), "{$name} rule id");
            // No served show body may leak a detector fingerprint token.
            self::assertSame([], $guard->scan($r->body), "{$name} show body must be fingerprint-clean");
        }
    }

    public function test_api_show_first_model_carries_show_markers(): void
    {
        $cat = $this->catalog();
        $first = (string) $cat->all()[0]['name'];
        $r = $this->emulator()->emulate(new RequestContext('POST', '/api/show', '', [], '{"model":"' . $first . '"}'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('"model_info"', $r->body);
        self::assertStringContainsString('"parameter_size":"' . (string) $cat->all()[0]['parameter_size'] . '"', $r->body);
        // The Ollama Modelfile template literal survived the render-layer escape verbatim.
        self::assertStringContainsString('{{ .Prompt }}', $r->body);
    }

    public function test_api_show_unknown_model_is_a_404(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/api/show', '', [], '{"model":"zzz:9b"}'));
        self::assertNotNull($r);
        self::assertSame(404, $r->status);
        self::assertSame(self::JSON_CT, $r->headers['Content-Type'] ?? null);
        self::assertSame('{"error":"model \'zzz:9b\' not found"}', $r->body);
        self::assertSame(['attack-ai-ollama-show'], $r->satisfies->templateIds());
    }

    public function test_api_show_reflected_model_cannot_break_the_json(): void
    {
        // The capture class [^"] stops at the first quote, so a model value carrying a quote can never
        // escape the JSON string it is reflected into — the 404 stays valid, parseable JSON.
        $r = $this->emulator()->emulate(new RequestContext('POST', '/api/show', '', [], '{"model":"a"b"}'));
        self::assertNotNull($r);
        self::assertSame(404, $r->status);
        self::assertNotNull(json_decode($r->body), 'the reflected 404 must stay valid JSON');
        self::assertSame('{"error":"model \'a\' not found"}', $r->body);
    }

    public function test_api_show_requires_a_post(): void
    {
        // A GET to /api/show misses the POST-gated match; no other rule claims it, so nothing serves.
        self::assertNull($this->emulator()->emulate(new RequestContext('GET', '/api/show')));
    }
}
