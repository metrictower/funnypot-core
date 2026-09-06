<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Ai\ChatFloor;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Compiler\ParamRouteCompiler;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * FP-0275 — the closed chat-floor directive grammar and its coherent token estimate.
 *
 * The buffered AI chat floor answers via {{misdirect | pick:...}} and reports usage counts via
 * {{chat.output_tokens}} / {{chat.total_tokens:19}}. This suite closes the grammar (only those exact
 * shapes compile or render; every near-miss is empty at runtime and rejected at compile time in bodies
 * and headers) and proves the estimate is a pure bytes/4 function of the SAME answer the renderer
 * selects — so the counter tracks the served content instead of a fixed cross-deploy tell. The served
 * content and full JSON/usage integration live in Ai\AiChatFloorTest.
 */
final class ChatFloorDirectiveTest extends TestCase
{
    // --- ChatFloor: selection matches the renderer, estimate is ceil(bytes/4) ----------------

    public function test_benign_answer_equals_the_generic_pick_render(): void
    {
        $rr = new DirectiveRenderer(); // gate off
        $pick = '{{pick:' . implode(',', ChatFloor::NONSENSE) . '}}';
        for ($seed = 0; $seed <= 128; $seed++) {
            self::assertSame($rr->render($pick, [], $seed), ChatFloor::answer($seed, false), "seed {$seed}: benign answer must equal the compiled pick");
        }
    }

    public function test_armed_answer_equals_the_misdirect_render(): void
    {
        $on = new DirectiveRenderer(null, false, true); // gate on
        for ($seed = 0; $seed <= 128; $seed++) {
            $answer = ChatFloor::answer($seed, true);
            self::assertContains($answer, InjectionPayloads::CHAT_MISDIRECTION, "seed {$seed}: armed answer must be a corpus line");
            self::assertSame($on->render('{{misdirect}}', [], $seed), $answer, "seed {$seed}: armed answer must equal the {{misdirect}} render");
        }
    }

    public function test_output_tokens_is_ceil_bytes_over_four(): void
    {
        for ($seed = 0; $seed <= 128; $seed++) {
            foreach ([false, true] as $armed) {
                $expected = max(1, (int) ceil(strlen(ChatFloor::answer($seed, $armed)) / 4));
                self::assertSame($expected, ChatFloor::outputTokens($seed, $armed), "seed {$seed} armed=" . ($armed ? '1' : '0'));
                self::assertGreaterThanOrEqual(1, ChatFloor::outputTokens($seed, $armed), 'estimate floors at 1');
            }
        }
    }

    // --- runtime: exact forms resolve, near-misses render '' (never the armed branch, never literal) --

    public function test_exact_forms_render_at_runtime(): void
    {
        $off = new DirectiveRenderer();
        $on = new DirectiveRenderer(null, false, true);
        // Surrounding whitespace is trimmed, so {{ misdirect }} is still the exact form.
        self::assertSame('', $off->render('{{ misdirect }}', [], 7), 'gate-off misdirect resolves empty');
        self::assertContains($on->render('{{ misdirect }}', [], 7), InjectionPayloads::CHAT_MISDIRECTION, 'gate-on misdirect resolves a corpus line');
        // The usage directives resolve to bare integers under both gates.
        self::assertSame((string) ChatFloor::outputTokens(7, false), $off->render('{{chat.output_tokens}}', [], 7));
        self::assertSame((string) ChatFloor::outputTokens(7, true), $on->render('{{chat.output_tokens}}', [], 7));
        self::assertSame((string) (19 + ChatFloor::outputTokens(7, false)), $off->render('{{chat.total_tokens:19}}', [], 7));
    }

    /**
     * @dataProvider runtimeNearMissProvider
     */
    public function test_near_miss_renders_empty_and_never_arms(string $directive): void
    {
        // Even with the gate ON, a near-miss must resolve to '' — never enter the armed branch and never
        // leak the literal directive text. (resolve() returns '' when no alternative resolves.)
        $on = new DirectiveRenderer(null, false, true);
        $out = $on->render($directive, [], 7);
        self::assertSame('', $out, "'{$directive}' must render empty, not arm or leak");
    }

    /** @return iterable<string,array{0:string}> */
    public static function runtimeNearMissProvider(): iterable
    {
        yield 'misdirect suffix' => ['{{misdirectX}}'];
        yield 'misdirection' => ['{{misdirection}}'];
        yield 'misdirect colon' => ['{{misdirect:foo}}'];
        yield 'chat total no count' => ['{{chat.total_tokens}}'];
        yield 'chat total wrong count' => ['{{chat.total_tokens:20}}'];
        yield 'chat output with count' => ['{{chat.output_tokens:5}}'];
        yield 'chat unknown base' => ['{{chat.foo}}'];
    }

    // --- chatFloorFormError: the shared compiler predicate -----------------------------------

    public function test_form_error_predicate(): void
    {
        // The exact forms pass (in a body).
        self::assertNull(DirectiveRenderer::chatFloorFormError('misdirect', false));
        self::assertNull(DirectiveRenderer::chatFloorFormError('chat.output_tokens', false));
        self::assertNull(DirectiveRenderer::chatFloorFormError('chat.total_tokens:19', false));
        self::assertSame('chat.output_tokens', DirectiveRenderer::CHAT_OUTPUT_TOKENS_DIRECTIVE);
        self::assertSame('chat.total_tokens:19', DirectiveRenderer::CHAT_TOTAL_TOKENS_DIRECTIVE);
        // Not a chat-floor directive at all ⇒ nothing to check.
        self::assertNull(DirectiveRenderer::chatFloorFormError('fake.tok:hex:8', false));
        self::assertNull(DirectiveRenderer::chatFloorFormError('pick:a,b', false));
        // Every near-miss is rejected in a body.
        foreach (['misdirectX', 'misdirection', 'misdirect:foo', 'chat.total_tokens', 'chat.total_tokens:20', 'chat.output_tokens:5', 'chat.foo'] as $bad) {
            self::assertNotNull(DirectiveRenderer::chatFloorFormError($bad, false), "'{$bad}' must be rejected");
        }
        // Even the exact forms are rejected in a header (body-only).
        self::assertNotNull(DirectiveRenderer::chatFloorFormError('misdirect', true));
        self::assertNotNull(DirectiveRenderer::chatFloorFormError('chat.output_tokens', true));
        self::assertNotNull(DirectiveRenderer::chatFloorFormError('chat.total_tokens:19', true));
    }

    // --- compiler closure: all three compilers accept the exact forms and reject near-misses --

    /** Invoke a compiler's private normalize() with a doc, mirroring the other compiler tests. */
    private function normalize(object $compiler, array $doc): array
    {
        $m = new ReflectionMethod($compiler, 'normalize');
        $m->setAccessible(true);

        return $m->invoke($compiler, $doc, 'chat-floor-test.yaml');
    }

    /** @return array<int,array{0:object,1:array<string,mixed>}> a (compiler, doc) pair per compiler. */
    private function compilerDocs(string $body): array
    {
        $resp = ['headers' => ['Content-Type' => 'application/json'], 'body' => $body];

        return [
            [new RouteEmulatorCompiler(), ['id' => 'route-chat-test', 'match' => ['pid' => ['route-chat-test']], 'response' => $resp]],
            [new ParamRouteCompiler(), ['id' => 'param-chat-test', 'param' => ['path' => '/chat/{p*}'], 'response' => $resp]],
            [new EmulatorCompiler(), ['id' => 'attack-chat-test', 'match' => [['in' => 'path', 'regex' => '/chat', 'capture' => false]], 'response' => $resp]],
        ];
    }

    public function test_all_three_compilers_accept_the_exact_forms(): void
    {
        $body = '{"a":"{{misdirect}}","b":{{chat.output_tokens}},"c":{{chat.total_tokens:19}}}';
        foreach ($this->compilerDocs($body) as [$compiler, $doc]) {
            $rule = $this->normalize($compiler, $doc);
            self::assertIsArray($rule, get_class($compiler) . ' must accept the exact chat-floor forms');
        }
    }

    /**
     * @dataProvider compileNearMissProvider
     */
    public function test_all_three_compilers_reject_a_near_miss(string $directive, string $phrase): void
    {
        $body = '{"x":"' . $directive . '"}';
        foreach ($this->compilerDocs($body) as [$compiler, $doc]) {
            $threw = false;
            try {
                $this->normalize($compiler, $doc);
            } catch (RuntimeException $e) {
                $threw = true;
                // Assert on a phrase from the chat-floor closure, NOT the generic "unknown directive"
                // reject (misdirect/chat. stay in KNOWN_PREFIXES, so the near-miss clears the prefix loop
                // and this closure is what must reject it).
                self::assertStringNotContainsString('unknown directive', $e->getMessage(), get_class($compiler) . " must reject '{$directive}' via the chat-floor closure, not the generic loop");
                self::assertStringContainsString($phrase, $e->getMessage(), get_class($compiler) . " must reject '{$directive}' with the chat-floor phrase");
            }
            self::assertTrue($threw, get_class($compiler) . " must reject '{$directive}'");
        }
    }

    /** @return iterable<string,array{0:string,1:string}> */
    public static function compileNearMissProvider(): iterable
    {
        yield 'misdirect suffix' => ['{{misdirectX}}', 'chat-floor misdirection'];
        yield 'misdirect colon' => ['{{misdirect:foo}}', 'chat-floor misdirection'];
        yield 'chat total no count' => ['{{chat.total_tokens}}', 'chat usage forms'];
        yield 'chat total wrong count' => ['{{chat.total_tokens:20}}', 'chat usage forms'];
        yield 'chat output with count' => ['{{chat.output_tokens:5}}', 'chat usage forms'];
        yield 'chat unknown base' => ['{{chat.foo}}', 'chat usage forms'];
    }

    public function test_all_three_compilers_reject_the_forms_in_a_header(): void
    {
        // A valid body form is still rejected as a header value (body-only).
        foreach ([['{{misdirect}}'], ['{{chat.output_tokens}}']] as [$directive]) {
            $resp = ['headers' => ['Content-Type' => 'application/json', 'X-Usage' => $directive], 'body' => '{"ok":true}'];
            $docs = [
                [new RouteEmulatorCompiler(), ['id' => 'route-chat-hdr', 'match' => ['pid' => ['route-chat-hdr']], 'response' => $resp]],
                [new ParamRouteCompiler(), ['id' => 'param-chat-hdr', 'param' => ['path' => '/chat/{p*}'], 'response' => $resp]],
                [new EmulatorCompiler(), ['id' => 'attack-chat-hdr', 'match' => [['in' => 'path', 'regex' => '/chat', 'capture' => false]], 'response' => $resp]],
            ];
            foreach ($docs as [$compiler, $doc]) {
                $threw = false;
                try {
                    $this->normalize($compiler, $doc);
                } catch (RuntimeException $e) {
                    $threw = true;
                    self::assertStringContainsString('body-only', $e->getMessage(), get_class($compiler) . " must reject '{$directive}' in a header as body-only");
                }
                self::assertTrue($threw, get_class($compiler) . " must reject '{$directive}' in a header");
            }
        }
    }
}
