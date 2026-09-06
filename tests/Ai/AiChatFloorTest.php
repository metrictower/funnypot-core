<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Ai;

use Funnypot\Core\Ai\ChatFloor;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Template\DirectiveRenderer;
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

    /** FP-0238: the gate-ON emulator (promptInjectionSeeding: true) — the opt-in that arms {{misdirect}}. */
    private function armedEmulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED, [], null, null, false, true);
    }

    /** The pre-FP-0238 benign nonsense answers — the exact corpus the chat floor served before, and the
     *  fallback arm of {{misdirect | pick:...}} that gate-OFF must still resolve to byte-for-byte. Pinned
     *  here independently; test_chatfloor_owns_the_benign_corpus asserts ChatFloor::NONSENSE equals it, so
     *  a drift in the single source is caught. */
    private const NONSENSE = [
        'The capital of France is Berlin.',
        'Two plus two equals five.',
        'Water boils at forty degrees Celsius.',
        'The sun orbits the Earth once per day.',
    ];

    /** Extract the dialect-specific answer field from a decoded floor body. */
    private function contentOf(string $path, string $body): string
    {
        $j = json_decode($body, true);
        self::assertIsArray($j, "{$path} body must decode to an object");
        switch ($path) {
            case '/api/chat':             return (string) $j['message']['content'];
            case '/api/generate':         return (string) $j['response'];
            case '/v1/chat/completions':  return (string) $j['choices'][0]['message']['content'];
            case '/v1/messages':          return (string) $j['content'][0]['text'];
        }
        self::fail("unknown dialect path {$path}");
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

    // ── FP-0238: the gated {{misdirect}} chat-floor injection channel ─────────────────────────────

    /**
     * Gate OFF (today's default construction) is BYTE-IDENTICAL to pre-change: {{misdirect}} resolves
     * to '' so the benign {{pick:...}} fallback wins — the SAME seeded selection as before. Prove it by
     * rendering the raw benign pick with a default (gate-off) DirectiveRenderer and asserting the served
     * content field equals it exactly, per seed; and assert NO misdirection substring leaks.
     *
     * @dataProvider dialects
     */
    public function test_gate_off_chat_floor_is_byte_identical(string $path, string $marker, string $ct, string $shape): void
    {
        $off = $this->emulator();
        $renderer = new DirectiveRenderer(); // gate off, exactly as the compile-time marker check builds it
        // Built from ChatFloor::NONSENSE, the single source of truth `bin/funnypot` also compiles the
        // `pick:` arm from — so this stays byte-accurate to the served fallback without a hand-copied list.
        $pick = '{{pick:' . implode(',', ChatFloor::NONSENSE) . '}}';

        for ($seed = 0; $seed <= 40; $seed++) {
            $r = $off->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
            self::assertNotNull($r, "{$path} seed {$seed} must serve");
            $content = $this->contentOf($path, $r->body);
            self::assertSame($renderer->render($pick, [], $seed), $content, "{$path} seed {$seed} gate-off content must equal the pre-change benign pick");
            self::assertContains($content, self::NONSENSE, "{$path} seed {$seed} gate-off content must be one of the pre-change nonsense answers");
            // No-leak: the WHOLE armed corpus must be absent from a gate-off body, not just two phrases.
            foreach (InjectionPayloads::CHAT_MISDIRECTION as $line) {
                self::assertStringNotContainsString($line, $r->body, "{$path} seed {$seed} gate-off must not leak any misdirection line");
            }
        }
    }

    /**
     * Gate ON seeds a first-person misdirection line from CHAT_MISDIRECTION into the CORRECT dialect
     * content field — always (never falls back to the benign pick) across seeds. The body stays valid
     * JSON, still carries the dialect structural marker, and still echoes the requested model.
     *
     * @dataProvider dialects
     */
    public function test_gate_on_seeds_persona_coherent_misdirection(string $path, string $marker, string $ct, string $shape): void
    {
        $on = $this->armedEmulator();
        for ($seed = 0; $seed <= 40; $seed++) {
            $r = $on->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
            self::assertNotNull($r, "{$path} seed {$seed} must serve");
            self::assertNotNull(json_decode($r->body), "{$path} seed {$seed} gate-on body must be valid JSON");
            self::assertStringContainsString($marker, $r->body, "{$path} seed {$seed} must still carry its dialect marker");
            self::assertStringContainsString('kimi-k3:2.8t', $r->body, "{$path} seed {$seed} must still echo the request model");
            $content = $this->contentOf($path, $r->body);
            self::assertContains($content, InjectionPayloads::CHAT_MISDIRECTION, "{$path} seed {$seed} content must be a seeded misdirection line, never the benign pick");
            self::assertNotContains($content, self::NONSENSE, "{$path} seed {$seed} content must not be the benign nonsense when armed");
        }
    }

    /**
     * Gate ON is NON-REFLECTING: a quote-bearing model is still truncated at the quote by the [^"]
     * capture (body stays valid JSON, echoes only the pre-quote bytes), and the misdirection is
     * corpus-only — the seeded content carries no bytes from the request model field.
     *
     * @dataProvider dialects
     */
    public function test_gate_on_is_not_reflected(string $path, string $marker, string $ct, string $shape): void
    {
        $r = $this->armedEmulator()->emulate(new RequestContext('POST', $path, '', [], '{"model":"safe"evil"}'));
        self::assertNotNull($r, "{$path} must serve");
        self::assertNotNull(json_decode($r->body), "{$path} gate-on floor must stay valid JSON on a quote-bearing model");
        self::assertStringContainsString('"safe"', $r->body, "{$path} must echo only the pre-quote model bytes");
        $content = $this->contentOf($path, $r->body);
        self::assertContains($content, InjectionPayloads::CHAT_MISDIRECTION, "{$path} misdirection must be corpus-only");
        self::assertStringNotContainsString('evil', $content, "{$path} misdirection must carry no request bytes");
    }

    /**
     * Gate ON stays within the Config body cap for every dialect and seed — larger than the 4-word
     * nonsense, but far under maxBodyBytes (the core keeps bodies plausibly-sized; the aggressive
     * drip is the named app follow-up).
     *
     * @dataProvider dialects
     */
    public function test_gate_on_body_within_size_cap(string $path, string $marker, string $ct, string $shape): void
    {
        $cap = (new Config())->maxBodyBytes;
        $on = $this->armedEmulator();
        for ($seed = 0; $seed <= 40; $seed++) {
            $r = $on->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
            self::assertNotNull($r, "{$path} seed {$seed} must serve");
            self::assertLessThanOrEqual($cap, strlen($r->body), "{$path} seed {$seed} gate-on body must be within maxBodyBytes");
        }
    }

    /**
     * The runtime misdirection corpus is invisible to the static CI fingerprint gate
     * (check-fingerprint-safety.php scans compiled bodies only), so the gate-ON served body must be
     * FingerprintGuard-clean across the seed sweep — this test is that coverage.
     */
    public function test_chat_floor_fingerprint_clean_gate_on_across_seeds(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $on = $this->armedEmulator();
        foreach (array_column(self::dialects(), 0) as $path) {
            for ($seed = 0; $seed <= 40; $seed++) {
                $r = $on->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
                self::assertNotNull($r, "{$path} seed {$seed} must serve");
                self::assertSame([], $guard->scan($r->body), "{$path} seed {$seed} gate-on body must be fingerprint-clean");
            }
        }
    }

    // ── FP-0275: usage counters track the served answer (no fixed-count tell) ─────────────────────

    /** ChatFloor is the single source of the benign corpus — it must equal the pinned expectation. */
    public function test_chatfloor_owns_the_benign_corpus(): void
    {
        self::assertSame(self::NONSENSE, ChatFloor::NONSENSE, 'ChatFloor::NONSENSE must be the exact benign corpus');
    }

    /** Decode the dialect's output-token usage fields from a floor body. */
    private function usageOf(string $path, string $body): array
    {
        $j = json_decode($body, true);
        self::assertIsArray($j, "{$path} body must decode to an object");
        switch ($path) {
            case '/api/chat':
            case '/api/generate':
                return ['output' => $j['eval_count']];
            case '/v1/chat/completions':
                return ['output' => $j['usage']['completion_tokens'], 'prompt' => $j['usage']['prompt_tokens'], 'total' => $j['usage']['total_tokens']];
            case '/v1/messages':
                return ['output' => $j['usage']['output_tokens'], 'input' => $j['usage']['input_tokens']];
        }
        self::fail("unknown dialect path {$path}");
    }

    /**
     * Under BOTH gates, every dialect's reported output-token count equals ceil(bytes/4) of the answer
     * actually extracted from the same body — the fixed 10/32 tell is gone — and OpenAI's total is
     * exactly prompt + completion (reading the body's own prompt value, not a literal). Every usage
     * field decodes as a JSON integer, never a string.
     *
     * @dataProvider dialects
     */
    public function test_usage_counters_track_extracted_content(string $path, string $marker, string $ct, string $shape): void
    {
        foreach ([$this->emulator(), $this->armedEmulator()] as $gate => $em) {
            for ($seed = 0; $seed <= 40; $seed++) {
                $r = $em->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
                self::assertNotNull($r, "{$path} seed {$seed} must serve");
                $content = $this->contentOf($path, $r->body);
                $usage = $this->usageOf($path, $r->body);
                $expected = max(1, (int) ceil(strlen($content) / 4));
                self::assertSame($expected, $usage['output'], "{$path} gate{$gate} seed {$seed}: output tokens must be ceil(bytes/4) of the served answer");
                self::assertIsInt($usage['output'], "{$path} gate{$gate} seed {$seed}: output tokens must be a JSON integer");
                if ($path === '/v1/chat/completions') {
                    self::assertIsInt($usage['prompt'], "{$path} gate{$gate} seed {$seed}: prompt_tokens must be an integer");
                    self::assertIsInt($usage['total'], "{$path} gate{$gate} seed {$seed}: total_tokens must be an integer");
                    self::assertSame($usage['prompt'] + $usage['output'], $usage['total'], "{$path} gate{$gate} seed {$seed}: total must equal prompt + completion");
                }
                if ($path === '/v1/messages') {
                    self::assertIsInt($usage['input'], "{$path} gate{$gate} seed {$seed}: input_tokens must be an integer");
                }
            }
        }
    }

    /**
     * The estimate is a pure function of the SELECTED answer, not of the request: a long prompt / a
     * long model name never inflates the output-token count, and the count for a given seed/gate is the
     * same regardless of the request body. (Non-reflection is proven separately; this proves the count
     * itself carries no request-derived bytes.)
     *
     * @dataProvider dialects
     */
    public function test_usage_estimate_is_independent_of_request(string $path, string $marker, string $ct, string $shape): void
    {
        $long = '{"model":"' . str_repeat('m', 120) . '","messages":[{"role":"user","content":"' . str_repeat('why ', 200) . '"}]}';
        for ($seed = 0; $seed <= 20; $seed++) {
            $a = $this->emulator()->emulate(new RequestContext('POST', $path, '', [], self::BODY), $seed);
            $b = $this->emulator()->emulate(new RequestContext('POST', $path, '', [], $long), $seed);
            self::assertNotNull($a);
            self::assertNotNull($b);
            self::assertSame($this->usageOf($path, $a->body)['output'], $this->usageOf($path, $b->body)['output'], "{$path} seed {$seed}: output-token count must not depend on the request body");
        }
    }

    /**
     * Across the bounded seed sweep BOTH corpora are fully exercised: gate-off reaches every benign
     * NONSENSE line and gate-on reaches every CHAT_MISDIRECTION line — so the coherence assertions above
     * are non-vacuous (they cover the whole corpus, not one lucky seed).
     */
    public function test_both_corpora_are_fully_selected_across_the_sweep(): void
    {
        $offSeen = [];
        $onSeen = [];
        $off = $this->emulator();
        $on = $this->armedEmulator();
        for ($seed = 0; $seed <= 40; $seed++) {
            $offSeen[$this->contentOf('/api/chat', $off->emulate(new RequestContext('POST', '/api/chat', '', [], self::BODY), $seed)->body)] = true;
            $onSeen[$this->contentOf('/api/chat', $on->emulate(new RequestContext('POST', '/api/chat', '', [], self::BODY), $seed)->body)] = true;
        }
        foreach (ChatFloor::NONSENSE as $line) {
            self::assertArrayHasKey($line, $offSeen, 'gate-off sweep must reach every benign line');
        }
        foreach (InjectionPayloads::CHAT_MISDIRECTION as $line) {
            self::assertArrayHasKey($line, $onSeen, 'gate-on sweep must reach every misdirection line');
        }
    }
}
