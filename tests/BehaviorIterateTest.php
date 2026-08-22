<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\EmulatorCompiler;
use Funnypot\RequestContext;
use Funnypot\Rules\PhpLiteralValidator;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The `iterate` behavior primitive: parse the request body into a bounded sub-call list and fan out
 * one `item` per sub-call, wrapped by wrap.open/close. Pins the mechanism with fixture rules:
 *  - N sub-calls in ⇒ N items out, hard-capped by the code constant (no amplification);
 *  - per-item reflection is XML-escaped and length-bounded (no markup injection);
 *  - the position-blind port (no body) and any parse fault degrade to fallback/empty — never a 500.
 */
final class BehaviorIterateTest extends TestCase
{
    /**
     * A fixture iterate rule that reflects each sub-call's method into an XML element, so the whole
     * fan-out is assertably well-formed.
     *
     * @return array<string,mixed>
     */
    private function iterateRule(bool $withFallback = true): array
    {
        $rule = [
            'id' => 'iterate-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'path', 'contains' => '/multi']],
            'response' => ['headers' => [], 'body' => '<base/>'],
            'behavior' => 'iterate',
            'iterate' => [
                'source' => 'body',
                'parse' => 'xmlrpc-multicall',
                'max_items' => 64,
                'item' => ['headers' => [], 'body' => '<m i="{{match.item.index}}">{{xml:match.item.method}}</m>'],
                'wrap' => ['open' => '<r>', 'close' => '</r>'],
                'response' => ['headers' => ['Content-Type' => 'text/xml; charset=UTF-8'], 'body' => ''],
                'empty' => ['response' => ['headers' => [], 'body' => '<empty/>']],
            ],
        ];
        if ($withFallback) {
            $rule['iterate']['fallback'] = ['response' => ['headers' => [], 'body' => '<fallback/>']];
        }

        return $rule;
    }

    /** Build a multicall-shaped body wrapping $n sub-calls each naming $method. */
    private function body(int $n, string $method = 'wp.getUsersBlogs'): string
    {
        $sub = '<value><struct><member><name>methodName</name><value><string>' . $method
            . '</string></value></member></struct></value>';

        return '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
            . str_repeat($sub, $n)
            . '</data></array></value></param></params></methodCall>';
    }

    private function serve(array $rule, ?string $body): ?object
    {
        $em = new TemplateAttackEmulator([$rule]);

        return $em->emulate(new RequestContext('POST', '/multi', '', [], $body));
    }

    // --- handler behavior -------------------------------------------------------------------

    public function test_n_subcalls_yield_n_items(): void
    {
        $r = $this->serve($this->iterateRule(), $this->body(3));
        self::assertNotNull($r);
        self::assertSame(3, substr_count($r->body, '<m '));
        self::assertStringStartsWith('<r>', $r->body);
        self::assertStringEndsWith('</r>', $r->body);
        self::assertNotFalse(simplexml_load_string($r->body), 'fan-out must be well-formed XML');
        // Each item saw its index and the reflected method.
        self::assertStringContainsString('<m i="0">wp.getUsersBlogs</m>', $r->body);
        self::assertStringContainsString('<m i="2">wp.getUsersBlogs</m>', $r->body);
    }

    public function test_amplification_is_capped_at_the_code_constant(): void
    {
        // 1000 sub-calls must not produce 1000 items — the code constant clamps the fan-out.
        $r = $this->serve($this->iterateRule(), $this->body(1000));
        self::assertNotNull($r);
        self::assertSame(64, substr_count($r->body, '<m '), 'items must be hard-capped');
    }

    public function test_nested_methodname_in_a_subcall_counts_once(): void
    {
        // ONE real sub-call whose params nest a struct member ALSO named methodName. A flat body-wide
        // count would see two `methodName` members and emit two items; the structural depth-aware
        // count emits exactly one (real WP: N-in ⇒ N-out), because the nested member sits below the
        // outermost struct depth.
        $nested = '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
            . '<value><struct>'
            . '<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>'
            . '<member><name>params</name><value><array><data>'
            . '<value><struct>'
            . '<member><name>methodName</name><value><string>nested.decoy</string></value></member>'
            . '</struct></value>'
            . '</data></array></value></member>'
            . '</struct></value>'
            . '</data></array></value></param></params></methodCall>';
        $r = $this->serve($this->iterateRule(), $nested);
        self::assertNotNull($r);
        self::assertSame(1, substr_count($r->body, '<m '), 'a nested methodName must not add a sub-call');
        // The reflected method is the outer sub-call's, never the nested decoy.
        self::assertStringContainsString('<m i="0">wp.getUsersBlogs</m>', $r->body);
        self::assertStringNotContainsString('nested.decoy', $r->body);
    }

    public function test_count_is_byte_position_independent_for_a_large_body(): void
    {
        // 64 sub-calls padded so the body far exceeds MAX_SURFACE (32768). The count must stay exactly
        // 64 — a pre-parse byte truncation would split a sub-call and undercount to neither N nor cap.
        $sub = '<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string>'
            . '</value></member></struct></value>';
        $filler = '<!-- ' . str_repeat('A', 600) . ' -->'; // no struct/methodName tokens
        $body = '<methodCall><methodName>system.multicall</methodName><params><param><value><array><data>'
            . str_repeat($sub . $filler, 64)
            . '</data></array></value></param></params></methodCall>';
        self::assertGreaterThan(32768, strlen($body), 'body must exceed MAX_SURFACE for this regression');

        $r = $this->serve($this->iterateRule(), $body);
        self::assertNotNull($r);
        self::assertSame(64, substr_count($r->body, '<m '), 'a large body with 64 sub-calls must not undercount');
    }

    public function test_reflected_method_is_bounded_and_not_raw_markup(): void
    {
        // The parser's [\w.] class stops at '<', so a planted tag in the method position is never
        // reflected as markup; the xml: directive is the render-layer backstop on top of that.
        $r = $this->serve($this->iterateRule(), $this->body(1, 'abc<script>alert(1)</script>'));
        self::assertNotNull($r);
        self::assertNotFalse(simplexml_load_string($r->body), 'even a hostile method must keep the body well-formed');
        self::assertStringContainsString('<m i="0">abc</m>', $r->body);
        self::assertStringNotContainsString('<script', $r->body);
    }

    public function test_zero_subcalls_render_the_empty_response(): void
    {
        $r = $this->serve($this->iterateRule(), '<methodCall><methodName>system.multicall</methodName></methodCall>');
        self::assertNotNull($r);
        self::assertSame('<empty/>', $r->body);
    }

    public function test_garbage_body_degrades_never_500(): void
    {
        // An unparseable body yields zero sub-calls (not a PCRE error) ⇒ the empty response, and the
        // rule always answers (never a 500).
        $r = $this->serve($this->iterateRule(), 'this is not xml-rpc at all');
        self::assertNotNull($r);
        self::assertSame('<empty/>', $r->body);
    }

    public function test_port_path_renders_the_fallback(): void
    {
        // No request body (the position-blind port) ⇒ the request-free fallback.
        $em = new TemplateAttackEmulator([$this->iterateRule()]);
        $port = $em->renderRule($this->iterateRule(), [], 0, null);
        self::assertNotNull($port);
        self::assertSame('<fallback/>', $port->body);
    }

    public function test_port_path_without_fallback_uses_the_base_response(): void
    {
        $em = new TemplateAttackEmulator([$this->iterateRule(false)]);
        $port = $em->renderRule($this->iterateRule(false), [], 0, null);
        self::assertNotNull($port);
        self::assertSame('<base/>', $port->body);
    }

    // --- compiler ---------------------------------------------------------------------------

    public function test_compiler_emits_config_and_clamps_max_items(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: iterate-compile
severity: high
tags: [test]
status: 200
match:
  - in: path
    contains: /multi
response:
  body: base
behavior: iterate
iterate:
  source: body
  parse: xmlrpc-multicall
  max_items: 9999
  item:
    body: "<m>{{xml:match.item.method}}</m>"
  wrap:
    open: "<r>"
    close: "</r>"
  response:
    headers: { Content-Type: "text/xml; charset=UTF-8" }
  empty:
    response:
      body: "<empty/>"
YAML);
        self::assertCount(1, $rules);
        $rule = $rules[0];
        self::assertSame('iterate', $rule['behavior']);
        self::assertSame('xmlrpc-multicall', $rule['iterate']['parse']);
        // Authored 9999 clamped down to the code ceiling.
        self::assertSame(64, $rule['iterate']['max_items']);
        self::assertSame('<r>', $rule['iterate']['wrap']['open']);

        $php = "<?php\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled iterate rule must be a pure array literal');
    }

    public function test_compiler_rejects_unknown_parse(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: iterate-badparse
match:
  - in: path
    contains: /x
response:
  body: base
behavior: iterate
iterate:
  parse: json-graphql-whatever
  item:
    body: "x"
YAML);
    }

    public function test_compiler_rejects_missing_item_body(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: iterate-noitem
match:
  - in: path
    contains: /x
response:
  body: base
behavior: iterate
iterate:
  parse: xmlrpc-multicall
  wrap:
    open: "<r>"
    close: "</r>"
YAML);
    }

    public function test_compiler_rejects_bad_directive_in_item(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: iterate-baddir
match:
  - in: path
    contains: /x
response:
  body: base
behavior: iterate
iterate:
  parse: xmlrpc-multicall
  item:
    body: "{{bogus.directive}}"
YAML);
    }

    public function test_compiler_rejects_bad_directive_in_wrap(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: iterate-badwrap
match:
  - in: path
    contains: /x
response:
  body: base
behavior: iterate
iterate:
  parse: xmlrpc-multicall
  item:
    body: "<m/>"
  wrap:
    open: "{{bogus.directive}}"
    close: "</r>"
YAML);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-iterate-' . getmypid() . '-' . uniqid();
        if (!mkdir($dir, 0775, true) && !is_dir($dir)) {
            self::fail("cannot create temp corpus dir {$dir}");
        }
        file_put_contents($dir . '/rule.yaml', $yaml);
        try {
            return (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }
    }
}
