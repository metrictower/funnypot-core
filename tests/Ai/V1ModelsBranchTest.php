<?php

declare(strict_types=1);

namespace Funnypot\Tests\Ai;

use Funnypot\Ai\ModelCatalog;
use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * A5: GET /v1/models serves the shared ModelCatalog via owns_path, header-branched by client shape.
 * No `anthropic-version` header → the OpenAI list envelope; the header present → the Anthropic shape.
 * The owns_path claim overrides the generic gpt-4o /v1/models stub, and the path-constrained match
 * keeps the rule from claiming any other GET. ModelCatalog stays the single source of truth.
 */
final class V1ModelsBranchTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../../resources/compiled/funnypot-attack.php';
    private const INDEX = __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
    private const JSON_CT = 'application/json';
    private const PATH = '/v1/models';

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

    public function test_path_is_owned(): void
    {
        self::assertTrue($this->emulator()->ownsPath(self::PATH));
    }

    public function test_default_get_serves_the_openai_list_shape(): void
    {
        $cat = $this->catalog();
        $r = $this->emulator()->emulate(new RequestContext('GET', self::PATH, '', [], ''));

        self::assertNotNull($r, 'GET /v1/models must serve');
        self::assertSame(200, $r->status);
        self::assertSame(self::JSON_CT, $r->headers['Content-Type'] ?? null);
        self::assertSame(['attack-ai-v1-models'], $r->satisfies->templateIds());

        // OpenAI envelope, carrying the FIRST catalog model's openai_id — never the generic gpt-4o.
        self::assertStringContainsString('"object":"list"', $r->body);
        self::assertStringContainsString('"' . (string) $cat->all()[0]['openai_id'] . '"', $r->body);
        self::assertStringNotContainsString('gpt-4o', $r->body);

        // Byte-identity to the catalog projection proves ModelCatalog is the single source of truth.
        self::assertSame(
            (string) json_encode($cat->openAiModels(), JSON_UNESCAPED_SLASHES),
            $r->body
        );
    }

    public function test_anthropic_version_header_serves_the_anthropic_shape(): void
    {
        $cat = $this->catalog();
        $r = $this->emulator()->emulate(
            new RequestContext('GET', self::PATH, '', ['anthropic-version' => '2023-06-01'], '')
        );

        self::assertNotNull($r, 'GET /v1/models with anthropic-version must serve');
        self::assertSame(200, $r->status);
        self::assertSame(self::JSON_CT, $r->headers['Content-Type'] ?? null);

        // Anthropic list markers + a catalog display_name; the OpenAI envelope must be absent.
        self::assertStringContainsString('"type":"model"', $r->body);
        self::assertStringContainsString('"has_more"', $r->body);
        self::assertStringContainsString('"' . (string) $cat->all()[0]['display_name'] . '"', $r->body);
        self::assertStringNotContainsString('"object":"list"', $r->body);

        self::assertSame(
            (string) json_encode($cat->anthropicModels(), JSON_UNESCAPED_SLASHES),
            $r->body
        );
    }

    /** The header only selects the shape — a non-GET verb misses the match entirely. */
    public function test_non_get_does_not_match(): void
    {
        self::assertNull(
            $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], '{}')),
            'POST /v1/models must not match the GET-gated rule'
        );
    }

    /** The path constraint (not owns_path) is what scopes the match: a different GET must not serve. */
    public function test_other_get_path_is_not_claimed(): void
    {
        self::assertNull(
            $this->emulator()->emulate(new RequestContext('GET', '/v1/models/extra', '', [], '')),
            'a longer path must not match the anchored /v1/models rule'
        );
    }

    public function test_both_shapes_are_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $em = $this->emulator();

        $openai = $em->emulate(new RequestContext('GET', self::PATH, '', [], ''));
        $anthropic = $em->emulate(
            new RequestContext('GET', self::PATH, '', ['anthropic-version' => '2023-06-01'], '')
        );

        self::assertNotNull($openai);
        self::assertNotNull($anthropic);
        self::assertSame([], $guard->scan($openai->body), 'OpenAI /v1/models body must be fingerprint-clean');
        self::assertSame([], $guard->scan($anthropic->body), 'Anthropic /v1/models body must be fingerprint-clean');
    }

    /**
     * owns_path wins 100% of the time — no persona-weight lottery. Sweep seeds 0..199 through the
     * FULL engine (both client shapes) and require every one to serve the exact catalog body.
     */
    public function test_serve_is_deterministic_across_a_seed_sweep(): void
    {
        $cat = $this->catalog();
        $openaiBody = (string) json_encode($cat->openAiModels(), JSON_UNESCAPED_SLASHES);
        $anthropicBody = (string) json_encode($cat->anthropicModels(), JSON_UNESCAPED_SLASHES);

        $servedOpenai = 0;
        $servedAnthropic = 0;
        for ($seed = 0; $seed <= 199; $seed++) {
            $engine = $this->engine((string) $seed);

            $o = $engine->respond(new RequestContext('GET', self::PATH, '', [], ''));
            if ($o !== null
                && $o->body === $openaiBody
                && ($o->headers['Content-Type'] ?? null) === self::JSON_CT) {
                $servedOpenai++;
            }

            $a = $engine->respond(
                new RequestContext('GET', self::PATH, '', ['anthropic-version' => '2023-06-01'], '')
            );
            if ($a !== null
                && $a->body === $anthropicBody
                && ($a->headers['Content-Type'] ?? null) === self::JSON_CT) {
                $servedAnthropic++;
            }
        }

        self::assertSame(200, $servedOpenai, 'OpenAI shape must serve on every one of 200 seeds');
        self::assertSame(200, $servedAnthropic, 'Anthropic shape must serve on every one of 200 seeds');
    }
}
