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
 * The `arith-eval` behavior primitive: compute a small integer expression over reflected captures
 * (a hand-written integer parser — never eval), bind the result into a capture, and render the
 * rule's response. Pins the mechanism with fixture rules (never the shipped compiled file):
 *  - the ops set is closed {add,sub,mul} (no division ⇒ no divide-by-zero ⇒ no 500);
 *  - operands are magnitude-bounded; any grammar/bound miss degrades to the base response;
 *  - it is captures-only, so it renders identically on the facade and the position-blind port.
 */
final class BehaviorArithEvalTest extends TestCase
{
    /**
     * A form-A (fixed op) arith-eval fixture: two named-group operands summed into {{match.sum}}.
     *
     * @return array<string,mixed>
     */
    private function addRule(string $op = 'add', int $max = 2147483647): array
    {
        return [
            'id' => 'arith-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'a=(?P<a>-?\d+)&b=(?P<b>-?\d+)', 'capture' => true]],
            'response' => ['headers' => [], 'body' => 'BASE FALLBACK'],
            'behavior' => 'arith-eval',
            'arith-eval' => [
                'response' => ['headers' => [], 'body' => 'R={{match.sum}}'],
                'left' => 'a',
                'right' => 'b',
                'op' => $op,
                'max_operand' => $max,
                'bind' => 'sum',
            ],
        ];
    }

    /**
     * A form-B (expression) arith-eval fixture: a captured "<int> <op> <int>" expr with the ops it
     * authorizes.
     *
     * @param string[] $ops
     * @return array<string,mixed>
     */
    private function exprRule(array $ops): array
    {
        return [
            'id' => 'arith-expr-fixture',
            'severity' => 'high',
            'tags' => [],
            'status' => 200,
            'match' => [['in' => 'query', 'regex' => 'e=(?P<e>[^&]+)', 'capture' => true]],
            'response' => ['headers' => [], 'body' => 'BASE FALLBACK'],
            'behavior' => 'arith-eval',
            'arith-eval' => [
                'response' => ['headers' => [], 'body' => 'R={{match.result}}'],
                'expr' => 'e',
                'ops' => $ops,
                'max_operand' => 2147483647,
                'bind' => 'result',
            ],
        ];
    }

    private function serve(array $rule, string $query): ?object
    {
        $em = new TemplateAttackEmulator([$rule]);

        return $em->emulate(new RequestContext('GET', '/x', $query));
    }

    // --- handler behavior -------------------------------------------------------------------

    public function test_fixed_op_add_and_sub(): void
    {
        $r = $this->serve($this->addRule('add'), 'a=44&b=1');
        self::assertNotNull($r);
        self::assertSame('R=45', $r->body);

        $s = $this->serve($this->addRule('sub'), 'a=44&b=1');
        self::assertNotNull($s);
        self::assertSame('R=43', $s->body);
    }

    public function test_expression_form_multiplies(): void
    {
        // The classic SSTI liveness probe {{7*7}} — a randomized-operand echo the fixed 49 can't fake.
        $r = $this->serve($this->exprRule(['add', 'sub', 'mul']), 'e=7*7');
        self::assertNotNull($r);
        self::assertSame('R=49', $r->body);
    }

    public function test_disallowed_op_degrades_to_base(): void
    {
        // mul is not in the authorized ops list, so the expression declines to the base response.
        $r = $this->serve($this->exprRule(['add', 'sub']), 'e=7*7');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_operand_over_max_degrades_to_base(): void
    {
        $r = $this->serve($this->addRule('add', 10), 'a=44&b=1');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_non_numeric_capture_degrades_to_base(): void
    {
        // A garbage expression never parses ⇒ base response, never a 500.
        $r = $this->serve($this->exprRule(['add', 'mul']), 'e=notmath');
        self::assertNotNull($r);
        self::assertSame('BASE FALLBACK', $r->body);
    }

    public function test_negative_operands(): void
    {
        $r = $this->serve($this->addRule('add'), 'a=-5&b=3');
        self::assertNotNull($r);
        self::assertSame('R=-2', $r->body);
    }

    public function test_facade_equals_port_render(): void
    {
        // Captures-only: renderRule with vs without $r must be byte-identical (position-blind).
        $em = new TemplateAttackEmulator([$this->addRule('add')]);
        $rule = $this->addRule('add');
        $captures = ['a' => '7', 'b' => '7'];

        $facade = $em->renderRule($rule, $captures, 0, new RequestContext('GET', '/x', 'a=7&b=7'));
        $port = $em->renderRule($rule, $captures, 0, null);
        self::assertNotNull($facade);
        self::assertNotNull($port);
        self::assertSame('R=14', $facade->body);
        self::assertSame($facade->body, $port->body);
    }

    // --- compiler ---------------------------------------------------------------------------

    public function test_compiler_emits_fixed_op_config(): void
    {
        $rules = $this->compileOne(<<<'YAML'
id: arith-compile
severity: high
tags: [test]
status: 200
match:
  - in: query
    regex: 'a=(?P<a>\d+)&b=(?P<b>\d+)'
    capture: true
response:
  body: BASE
behavior: arith-eval
arith-eval:
  left: a
  right: b
  op: add
  max_operand: 999999999999
  bind: sum
  response:
    headers: { Content-Type: "text/plain" }
    body: "R={{match.sum}}"
YAML);
        self::assertCount(1, $rules);
        $rule = $rules[0];
        self::assertSame('arith-eval', $rule['behavior']);
        self::assertSame('a', $rule['arith-eval']['left']);
        self::assertSame('add', $rule['arith-eval']['op']);
        self::assertSame('sum', $rule['arith-eval']['bind']);
        // max_operand is clamped down to the hard ceiling.
        self::assertSame(2147483647, $rule['arith-eval']['max_operand']);

        $php = "<?php\n\nreturn " . var_export($rules, true) . ";\n";
        self::assertTrue((new PhpLiteralValidator())->isValid($php), 'compiled arith-eval rule must be a pure array literal');
    }

    public function test_compiler_rejects_unknown_op(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: arith-badop
match:
  - in: query
    contains: x
response:
  body: base
behavior: arith-eval
arith-eval:
  left: a
  right: b
  op: div
  response:
    body: "R={{match.result}}"
YAML);
    }

    public function test_compiler_rejects_both_forms(): void
    {
        // (left+right+op) AND (expr+ops) together is ambiguous — exactly one form is required.
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: arith-bothforms
match:
  - in: query
    contains: x
response:
  body: base
behavior: arith-eval
arith-eval:
  left: a
  right: b
  op: add
  expr: e
  ops: [add]
  response:
    body: "R={{match.result}}"
YAML);
    }

    public function test_compiler_rejects_missing_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: arith-noresp
match:
  - in: query
    contains: x
response:
  body: base
behavior: arith-eval
arith-eval:
  left: a
  right: b
  op: add
YAML);
    }

    public function test_compiler_rejects_bad_directive_in_response(): void
    {
        $this->expectException(RuntimeException::class);
        $this->compileOne(<<<'YAML'
id: arith-baddir
match:
  - in: query
    contains: x
response:
  body: base
behavior: arith-eval
arith-eval:
  left: a
  right: b
  op: add
  response:
    body: "{{bogus.directive}}"
YAML);
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function compileOne(string $yaml): array
    {
        $dir = sys_get_temp_dir() . '/funnypot-arith-' . getmypid() . '-' . uniqid();
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
