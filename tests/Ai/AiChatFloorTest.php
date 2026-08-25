<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Ai;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The chat FLOOR (A7): the four inference chat dialects still answer believably when the app's
 * Tier-2 chat handler is off. Each owns_path rule serves a buffered (stream:false) object with a
 * static, deliberately-wrong answer and echoes the request's model. Catalog-independent — the shapes
 * are fixed per dialect; at runtime the app tier returns ahead of core, so this only floors misses.
 */
final class AiChatFloorTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../../resources/compiled/funnypot-attack.php';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** A representative buffered chat request body naming a catalog model. */
    private const BODY = '{"model":"kimi-k3:2.8t","messages":[{"role":"user","content":"hi"}]}';

    /**
     * path => [dialect marker, exact Content-Type, a shape field unique to the dialect].
     *
     * @return array<string,array{0:string,1:string,2:string}>
     */
    public static function dialects(): array
    {
        return [
            'ollama chat'      => ['/api/chat', '"done":true', 'application/json; charset=utf-8', '"message"'],
            'ollama generate'  => ['/api/generate', '"done":true', 'application/json; charset=utf-8', '"response"'],
            'openai chat'      => ['/v1/chat/completions', '"chat.completion"', 'application/json', '"choices"'],
            'anthropic msgs'   => ['/v1/messages', '"stop_reason"', 'application/json', '"content"'],
        ];
    }

    /**
     * @dataProvider dialects
     */
    public function test_dialect_floors_a_buffered_answer(string $path, string $marker, string $ct, string $shape): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', $path, '', [], self::BODY));

        self::assertNotNull($r, "{$path} must serve a floor answer");
        self::assertSame(200, $r->status, "{$path} status");
        self::assertSame($ct, $r->headers['Content-Type'] ?? null, "{$path} Content-Type must be exact");
        self::assertStringContainsString($marker, $r->body, "{$path} must carry its dialect marker");
        self::assertStringContainsString($shape, $r->body, "{$path} must carry its dialect shape field");
        self::assertStringContainsString('kimi-k3:2.8t', $r->body, "{$path} must echo the request model");
        self::assertNotNull(json_decode($r->body), "{$path} floor body must be valid JSON");
    }

    /**
     * @dataProvider dialects
     */
    public function test_dialect_is_owned(string $path, string $marker, string $ct, string $shape): void
    {
        self::assertTrue($this->emulator()->ownsPath($path), "{$path} must be claimed via owns_path");
    }

    public function test_generate_carries_the_generate_only_shape(): void
    {
        // /api/generate is the Ollama single-turn shape: a top-level "response" string plus a
        // "context" token array, NOT the /api/chat "message" object.
        $r = $this->emulator()->emulate(new RequestContext('POST', '/api/generate', '', [], self::BODY));
        self::assertNotNull($r);
        self::assertStringContainsString('"context":[1,2,3]', $r->body);
        self::assertStringContainsString('"response":"', $r->body);
        self::assertStringNotContainsString('"message"', $r->body);
    }

    public function test_floor_declines_a_get_and_a_bodyless_request(): void
    {
        foreach (array_column(self::dialects(), 0) as $path) {
            self::assertNull($this->emulator()->emulate(new RequestContext('GET', $path)), "{$path} GET must not floor");
            self::assertNull($this->emulator()->emulate(new RequestContext('POST', $path, '', [], null)), "{$path} bodyless POST must not floor");
        }
    }

    public function test_floor_bodies_are_fingerprint_clean_across_seeds(): void
    {
        // The nonsense answer is a seeded pick, so sweep enough seeds to exercise every option and
        // require the served body to stay free of any detector fingerprint token on each.
        $guard = FingerprintGuard::fromPackage();
        $em = $this->emulator();
        foreach (array_column(self::dialects(), 0) as $path) {
            for ($seed = 0; $seed <= 40; $seed++) {
                $r = $em->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
                self::assertNotNull($r, "{$path} seed {$seed} must serve");
                self::assertSame([], $guard->scan($r->body), "{$path} seed {$seed} floor body must be fingerprint-clean");
            }
        }
    }

    public function test_reflected_model_cannot_break_the_json(): void
    {
        // The [^"] capture stops at the first quote, so a model value carrying a quote can never
        // escape the JSON string it is echoed into — the capture is truncated at the quote and every
        // dialect's floor stays valid, parseable JSON.
        foreach (array_column(self::dialects(), 0) as $path) {
            $r = $this->emulator()->emulate(new RequestContext('POST', $path, '', [], '{"model":"safe"evil"}'));
            self::assertNotNull($r, "{$path} must serve");
            self::assertNotNull(json_decode($r->body), "{$path} floor must stay valid JSON on a quote-bearing model");
            self::assertStringContainsString('"safe"', $r->body, "{$path} must echo only the pre-quote model bytes");
        }
    }
}
