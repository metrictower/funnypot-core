<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\CrsArchetypes;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Compiler\ParamRouteCompiler;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * {{urldecode-ascii:match.N}} — the bounded raw reflector slot. One form-decode pass (urldecode:
 * %XX ⇒ byte, + ⇒ space, an invalid triplet stays literal), then all-or-nothing admission: 1..512
 * decoded bytes, every one printable ASCII 0x20..0x7e, else ''. Markup bytes are kept by design;
 * every control/DEL/high byte empties the whole value; nothing is ever decoded twice.
 *
 * The compile-time side: every compiler's raw-HTML reflection lint treats it exactly like
 * {{match.*}} / {{urldecode:match.*}} (an unmarked text/html body fails the build) and rejects it
 * in a header outright (its byte class excludes CR/LF/NUL, so the runtime C8 guard would let a
 * header use through silently — the compile-time reject is the real body-only guard).
 */
final class UrldecodeAsciiDirectiveTest extends TestCase
{
    private const D = '{{urldecode-ascii:match.v}}';

    /** @param array<int|string,string> $captures */
    private function render(string $template, array $captures): string
    {
        return (new DirectiveRenderer())->render($template, $captures, 7);
    }

    /** Render the directive with $wire as the raw (pre-decode) capture — as the query regex hands it over. */
    private function slot(string $wire): string
    {
        return $this->render(self::D, ['v' => $wire]);
    }

    // --- decode + admission ---------------------------------------------------------------

    public function test_printable_payloads_reflect_raw_after_one_form_decode(): void
    {
        // %XX decodes to its byte; a '+' is a space (a real GET form sink), so a plus-encoded tag
        // becomes a valid tag rather than the believability tell rawurldecode would leave.
        self::assertSame('<img src=x onerror=alert(1)>', $this->slot('%3Cimg+src%3Dx+onerror%3Dalert(1)%3E'));
        self::assertSame('a b', $this->slot('a+b'));
        self::assertSame('<b>', $this->slot('%3Cb%3E'));
        self::assertSame('<b>', $this->slot('<b>'));

        // The whole printable ASCII range round-trips raw (markup bytes kept by design).
        $printable = '';
        for ($b = 0x20; $b <= 0x7e; $b++) {
            $printable .= chr($b);
        }
        self::assertSame($printable, $this->slot(rawurlencode($printable)));
    }

    public function test_empty_and_missing_capture_render_empty(): void
    {
        self::assertSame('', $this->slot(''));                 // empty capture
        self::assertSame('', $this->render(self::D, []));      // capture absent entirely
    }

    public function test_length_cap_admits_512_and_refuses_513(): void
    {
        // Raw alphanumerics decode 1:1, so length is exact.
        self::assertSame(str_repeat('a', 512), $this->slot(str_repeat('a', 512)));
        self::assertSame('', $this->slot(str_repeat('a', 513)));

        // The cap is on the DECODED length: 512 bytes encoded (1536 wire bytes) still admit; 513 do not.
        self::assertSame(str_repeat('<', 512), $this->slot(str_repeat('%3C', 512)));
        self::assertSame('', $this->slot(str_repeat('%3C', 513)));
    }

    /**
     * @dataProvider rejectedByteProvider
     */
    public function test_any_non_printable_byte_empties_the_whole_value(string $wire): void
    {
        self::assertSame('', $this->slot($wire));
    }

    /**
     * @return iterable<string,array{0:string}>
     */
    public static function rejectedByteProvider(): iterable
    {
        // Every C0 control, percent-encoded (the wire admits the encoding; the decode rejects the byte).
        for ($b = 0; $b < 0x20; $b++) {
            yield sprintf('enc C0 0x%02x', $b) => ['a' . sprintf('%%%02X', $b) . 'b'];
        }
        // Raw C0 controls that the query surface itself permits (everything but CR/LF/NUL).
        yield 'raw TAB' => ["a\tb"];
        yield 'raw VT' => ["a\x0bb"];
        yield 'raw ESC' => ["a\x1bb"];
        // DEL, raw and encoded.
        yield 'raw DEL' => ["a\x7fb"];
        yield 'enc DEL' => ['a%7Fb'];
        // Encoded CR/LF/NUL (a raw one never reaches the directive — the capture class refuses it).
        yield 'enc CR' => ['a%0Db'];
        yield 'enc LF' => ['a%0Ab'];
        yield 'enc NUL' => ['a%00b'];
        // High bytes: lone 0x80, 0xff, latin-1, and valid multibyte UTF-8 — all non-ASCII, all rejected.
        yield 'enc 0x80' => ['a%80b'];
        yield 'enc 0xff' => ['a%ffb'];
        yield 'raw high' => ["a\xc3\xbcb"];
        yield 'enc utf-8' => [rawurlencode('ünïcode')];
    }

    public function test_double_encoding_is_decoded_exactly_once(): void
    {
        // One decode away from the printable text "%0a" — served as those three characters, never a LF.
        self::assertSame('a%0ab', $this->slot('a%250ab'));
        self::assertSame('x%3Cy', $this->slot('x%253Cy'));
        // An invalid percent triplet stays literal '%' text (urldecode semantics), still printable.
        self::assertSame('100%%zz<', $this->slot('100%25%zz<'));
        self::assertSame('%', $this->slot('%'));
    }

    public function test_empty_slot_lets_an_authored_alternative_win(): void
    {
        // A rejected value renders '' so resolve()'s alternative cascade still reaches the next branch,
        // exactly like every other directive — the primary slot is never a dead end for a fallback.
        $out = $this->render('{{urldecode-ascii:match.v | fake.x:hex:6}}', ['v' => "a\tb"]);
        self::assertSame(6, strlen($out));
        self::assertSame(1, preg_match('/^[0-9a-f]{6}$/', $out));
    }

    // --- the directive is a known, closed prefix ------------------------------------------

    public function test_directive_is_a_known_prefix_and_body_only_flagged(): void
    {
        self::assertContains('urldecode-ascii:match.', DirectiveRenderer::KNOWN_PREFIXES);
        self::assertSame(512, DirectiveRenderer::ASCII_REFLECT_MAX_BYTES);
    }

    // --- compile-time lint: every compiler treats it as a raw reflection + body-only ------

    /** Invoke a compiler's private normalize() with a doc, mirroring the binary-route test's pattern. */
    private function normalize(object $compiler, array $doc): array
    {
        $m = new ReflectionMethod($compiler, 'normalize');
        $m->setAccessible(true);

        return $m->invoke($compiler, $doc, 'urldecode-ascii-test.yaml');
    }

    private function attackDoc(array $response, array $extra = []): array
    {
        return array_merge([
            'id' => 'attack-uda-test',
            'match' => [['in' => 'query', 'regex' => '(?:^|&)q=(?P<value>[^&]{1,64})(?:&|$)', 'capture' => true]],
            'response' => $response,
        ], $extra);
    }

    private function htmlBody(string $body): array
    {
        return ['headers' => ['Content-Type' => 'text/html; charset=utf-8'], 'body' => $body];
    }

    public function test_attack_compiler_requires_reflects_input_for_a_raw_html_body(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('reflects a raw request capture');
        $this->normalize(new EmulatorCompiler(), $this->attackDoc($this->htmlBody('x <span>' . self::D . '</span>')));
    }

    public function test_attack_compiler_admits_the_raw_html_body_when_marked(): void
    {
        $rule = $this->normalize(new EmulatorCompiler(), $this->attackDoc(
            $this->htmlBody('x <span>' . self::D . '</span>'),
            ['reflects_input' => true, 'reflect_class' => 'xss']
        ));
        self::assertTrue($rule['reflects_input']);
        self::assertStringContainsString(self::D, (string) $rule['response']['body']);
    }

    public function test_attack_compiler_rejects_the_directive_in_a_header(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('body-only');
        $this->normalize(new EmulatorCompiler(), $this->attackDoc([
            'headers' => ['Content-Type' => 'text/plain', 'X-Echo' => self::D],
            'body' => 'ok',
        ], ['reflects_input' => true, 'reflect_class' => 'xss']));
    }

    public function test_route_compiler_requires_reflects_input_and_rejects_a_header(): void
    {
        $route = static function (array $response, array $extra = []): array {
            return array_merge(['id' => 'route-uda-test', 'match' => ['pid' => ['route-uda-test']], 'response' => $response], $extra);
        };

        try {
            $this->normalize(new RouteEmulatorCompiler(), $route($this->htmlBody('<span>' . self::D . '</span>')));
            self::fail('an unmarked raw-reflecting route body must fail the build');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('reflects a raw request capture', $e->getMessage());
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('body-only');
        $this->normalize(new RouteEmulatorCompiler(), $route([
            'headers' => ['Content-Type' => 'text/plain', 'X-Echo' => self::D],
            'body' => 'ok',
        ], ['reflects_input' => true]));
    }

    public function test_param_compiler_requires_reflects_input_and_rejects_a_header(): void
    {
        $param = static function (array $response, array $extra = []): array {
            return array_merge(['id' => 'param-uda-test', 'param' => ['path' => '/uda/{p*}'], 'response' => $response], $extra);
        };

        try {
            $this->normalize(new ParamRouteCompiler(), $param($this->htmlBody('<span>' . self::D . '</span>')));
            self::fail('an unmarked raw-reflecting param body must fail the build');
        } catch (RuntimeException $e) {
            self::assertStringContainsString('reflects a raw request capture', $e->getMessage());
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('body-only');
        $this->normalize(new ParamRouteCompiler(), $param([
            'headers' => ['Content-Type' => 'text/plain', 'X-Echo' => self::D],
            'body' => 'ok',
        ], ['reflects_input' => true, 'reflect_class' => 'fs-read']));
    }

    // --- CRS archetype sanitize strips the slot so no generated template inherits it -------

    public function test_crs_archetype_sanitize_strips_the_directive(): void
    {
        $arch = new CrsArchetypes(dirname(__DIR__));
        $sanitize = new ReflectionMethod($arch, 'sanitize');
        $sanitize->setAccessible(true);

        $out = $sanitize->invoke($arch, [
            'headers' => ['Content-Type' => 'text/html', 'X-Echo' => 'a ' . self::D . ' b'],
            'body' => '<span>' . self::D . '</span> and {{urldecode:match.0}} and {{match.1}}',
        ]);

        self::assertStringNotContainsString('urldecode-ascii:match.', $out['body']);
        self::assertStringNotContainsString('urldecode:match.', $out['body']);
        self::assertStringNotContainsString('{{match.', $out['body']);
        self::assertStringNotContainsString('urldecode-ascii:match.', $out['headers']['X-Echo']);
    }
}
