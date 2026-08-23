<?php

declare(strict_types=1);

namespace Funnypot\Tests\Ai;

use Funnypot\Ai\ModelCatalog;
use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The AI owns_path attack tier (compiled by `funnypot compile-ai` into templates/attack-ai/).
 *  - A4b: the three Ollama GET recon pages (/api/version, /api/tags, /api/ps) are CLAIMED via
 *    owns_path, so the AI fake wins deterministically instead of losing a persona-weight lottery.
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
}
