<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Rules\PhpLiteralValidator;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The `expr-eval` behavior primitive: the SSTI decoy. Evaluate a full arithmetic expression from a
 * reflected capture (via Support\SafeArithmetic — a hand-written parser, never eval), bind the
 * integer result into a capture, and render the rule's response. Pins with fixture rules (never the
 * shipped compiled file):
 *  - a full grammar (+ - * / %, parens) evaluates; only the integer is reflected;
 *  - any unsafe case (div/mod by zero, overflow, oversized, non-arithmetic) degrades to the base
 *    response — never a 500;
 *  - it is captures-only, so it renders identically on the facade and the position-blind port.
 */
final class BehaviorExprEvalTest extends TestCase
{
    /**
     * An expr-eval fixture: the whole query captures into `e`, evaluated and echoed as {{match.r}}.
     *
     * @return array<string,mixed>
     */
    private function exprRule(int $max = 2147483647, int $maxLen = 32): array
    {
        return [
            'id' => 'expr-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'e=(?P<e>[^&]+)', 'capture' => true]],
            'response' => ['headers' => [], 'body' => 'BASE FALLBACK'],
            'behavior' => 'expr-eval',
            'expr-eval' => [
                'response' => ['headers' => [], 'body' => 'R={{match.r}}'],
                'expr' => 'e',
                'bind' => 'r',
                'max_operand' => $max,
                'max_len' => $maxLen,
            ],
        ];
    }

    private function serve(array $rule, string $query): ?object
    {
        $em = new TemplateAttackEmulator([$rule]);

        return $em->emulate(new RequestContext('GET', '/x', $query));
    }

    // --- handler behavior -------------------------------------------------------------------

    public function test_single_op_probe(): void
    {
        $r = $this->serve($this->exprRule(), 'e=7*7');
        self::assertNotNull($r);
        self::assertSame('R=49', $r->body);
    }

    public function test_multi_op_expression(): void
    {
        // The `query` surface is raw (no HTTP decode at this layer), so operators are literal.
        $r = $this->serve($this->exprRule(), 'e=7*7+1');
        self::assertNotNull($r);
        self::assertSame('R=50', $r->body);
    }

    public function test_parentheses_and_division(): void
    {
        self::assertSame('R=20', $this->serve($this->exprRule(), 'e=(2+3)*4')->body);
        self::assertSame('R=14', $this->serve($this->exprRule(), 'e=100/7')->body);
        self::assertSame('R=1', $this->serve($this->exprRule(), 'e=10%3')->body);
    }

    public function test_division_by_zero_degrades_to_base(): void
    {
        $r = $this->serve($this->exprRule(), 'e=1/0');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body); // never a 500
    }

    public function test_overflow_degrades_to_base(): void
    {
        $r = $this->serve($this->exprRule(2147483647), 'e=2000000000*2');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_non_arithmetic_payload_degrades_to_base(): void
    {
        // The exact hostile SSTI payloads: they must never evaluate to anything, and never error.
        self::assertSame('BASE FALLBACK', $this->serve($this->exprRule(), 'e=config')->body);
        self::assertSame('BASE FALLBACK', $this->serve($this->exprRule(), 'e=notmath')->body);
    }

    public function test_oversized_expression_degrades_to_base(): void
    {
        $r = $this->serve($this->exprRule(2147483647, 3), 'e=7*7*7'); // 5 chars, cap 3
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_only_the_integer_is_reflected_never_raw_bytes(): void
    {
        // A crafted payload that resolves to a number must reflect ONLY the number — no surrounding
        // attacker bytes leak into the body (so the rule needs no isolated origin).
        $r = $this->serve($this->exprRule(), 'e=8*8');
        self::assertNotNull($r);
        self::assertSame('R=64', $r->body);
    }

    public function test_facade_equals_port_render(): void
    {
        // Captures-only: renderRule with vs without $r must be byte-identical (position-blind).
        $em = new TemplateAttackEmulator([$this->exprRule()]);
        $rule = $this->exprRule();
        $captures = ['e' => '7*7'];

        $facade = $em->renderRule($rule, $captures, 0, new RequestContext('GET', '/x', 'e=7*7'));
        $port = $em->renderRule($rule, $captures, 0, null);
        self::assertNotNull($facade);
        self::assertNotNull($port);
        self::assertSame('R=49', $facade->body);
        self::assertSame($facade->body, $port->body);
    }

    // --- compiler ---------------------------------------------------------------------------

    public function test_compiler_emits_expr_eval_config(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: expr-compile
severity: high
tags: [test]
status: 200
match:
  - in: query
    regex: 'e=(?P<e>[^&]+)'
    capture: true
response:
  body: BASE
behavior: expr-eval
expr-eval:
  expr: e
  bind: out
  max_operand: 999999999999
  max_len: 999
  response:
    headers: { Content-Type: "text/html; charset=utf-8" }
    body: "{{match.out}}"
YAML);
        self::assertCount(1, $rules);
        $rule = $rules[0];
        self::assertSame('expr-eval', $rule['behavior']);
        self::assertSame('e', $rule['expr-eval']['expr']);
        self::assertSame('out', $rule['expr-eval']['bind']);
        // Both caps are clamped down to their hard ceilings.
        self::assertSame(2147483647, $rule['expr-eval']['max_operand']);
        self::assertSame(256, $rule['expr-eval']['max_len']);

        $php = "<?php\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled expr-eval rule must be a pure array literal');
    }

    public function test_compiler_rejects_missing_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: expr-noresp
match:
  - in: query
    contains: x
response:
  body: base
behavior: expr-eval
expr-eval:
  expr: e
YAML);
    }

    public function test_compiler_rejects_missing_expr(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: expr-noexpr
match:
  - in: query
    contains: x
response:
  body: base
behavior: expr-eval
expr-eval:
  response:
    body: "{{match.result}}"
YAML);
    }

    public function test_compiler_rejects_bad_directive_in_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: expr-baddir
match:
  - in: query
    contains: x
response:
  body: base
behavior: expr-eval
expr-eval:
  expr: e
  response:
    body: "{{bogus.directive}}"
YAML);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-expr-' . getmypid() . '-' . uniqid();
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
