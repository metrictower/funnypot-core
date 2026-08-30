<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\SafeArithmetic;
use PHPUnit\Framework\TestCase;

/**
 * The safe integer arithmetic evaluator behind the SSTI decoy. Pins that it "renders" a template-
 * injection probe's arithmetic with NO code execution (a hand-written parser, never eval), that
 * every unsafe case degrades to null rather than throwing, and — structurally — that the source
 * carries no code-execution primitive at all.
 */
final class SafeArithmeticTest extends TestCase
{
    /**
     * @dataProvider computes
     */
    public function test_computes(string $expr, int $expected): void
    {
        self::assertSame($expected, SafeArithmetic::evaluate($expr));
    }

    /** @return array<string,array{0:string,1:int}> */
    public function computes(): array
    {
        return [
            'classic ssti probe' => ['7*7', 49],
            'with spaces' => ['7 * 7', 49],
            'multi-op precedence' => ['7*7+1', 50],
            'precedence add then mul' => ['1+2*3', 7],
            'randomized subtraction' => ['1338-1', 1337],
            'parentheses override precedence' => ['(2+3)*4', 20],
            'nested parentheses' => ['((1+2)*(3+4))', 21],
            'integer division truncates' => ['100/7', 14],
            'modulo' => ['10%3', 1],
            'unary minus' => ['-5+8', 3],
            'unary minus after operator' => ['7*-1', -7],
            'zero result' => ['5-5', 0],
            'leading/trailing spaces' => ['  8*8  ', 64],
        ];
    }

    /**
     * @dataProvider rejects
     */
    public function test_rejects(string $expr): void
    {
        self::assertNull(SafeArithmetic::evaluate($expr));
    }

    /** @return array<string,array{0:string}> */
    public function rejects(): array
    {
        return [
            'empty' => [''],
            'whitespace only' => ['   '],
            'non-arithmetic word' => ['config'],
            'object access payload' => ["''.__class__"],
            'letters mixed in' => ['7*a'],
            'division by zero' => ['1/0'],
            'modulo by zero' => ['5%0'],
            'division by zero via expression' => ['10/(5-5)'],
            'trailing operator' => ['7*'],
            'leading binary operator' => ['*7'],
            'double operator' => ['7**7'],
            'unbalanced open paren' => ['(1+2'],
            'unbalanced close paren' => ['1+2)'],
            'two numbers no operator' => ['1 2'],
            'operand over bound' => ['2147483648'],
            'product overflows bound' => ['2000000000*2'],
            'dangerous chars rejected' => ['`id`'],
            'semicolon rejected' => ['7;7'],
            'dollar rejected' => ['$x'],
        ];
    }

    public function test_over_length_cap_is_rejected(): void
    {
        // 33 chars with the default 32 cap -> reject before parsing.
        self::assertNull(SafeArithmetic::evaluate(str_repeat('1+', 16) . '1'));
    }

    public function test_max_operand_bound_is_honored(): void
    {
        self::assertSame(49, SafeArithmetic::evaluate('7*7', 100));
        self::assertNull(SafeArithmetic::evaluate('7*7', 40)); // result 49 exceeds max 40
        self::assertNull(SafeArithmetic::evaluate('50', 40));  // operand exceeds max 40
    }

    public function test_max_len_cap_is_honored(): void
    {
        self::assertSame(49, SafeArithmetic::evaluate('7*7', SafeArithmetic::DEFAULT_MAX, 3));
        self::assertNull(SafeArithmetic::evaluate('7*7', SafeArithmetic::DEFAULT_MAX, 2));
    }

    /**
     * The load-bearing safety guarantee: the evaluator source contains NO code-execution path.
     * A TOKEN scan (not a text grep — so the words "eval"/"create_function"/"exec" in the docblock
     * prose can't false-positive): assert the `eval` language construct is absent, the shell-exec
     * backtick operator is absent, and no actual CODE identifier (T_STRING, i.e. not a comment or a
     * string literal) names a dangerous callable. If a future edit reaches for one, this fails.
     */
    public function test_source_has_no_code_execution_primitive(): void
    {
        $src = (string) file_get_contents(dirname(__DIR__, 2) . '/src/Support/SafeArithmetic.php');
        self::assertNotSame('', $src);

        $banned = [
            'eval', 'create_function', 'assert', 'preg_replace_callback', 'call_user_func',
            'call_user_func_array', 'system', 'exec', 'shell_exec', 'passthru',
            'proc_open', 'popen', 'pcntl_exec',
        ];

        foreach (token_get_all($src) as $token) {
            if (!is_array($token)) {
                // The shell-execution backtick operator tokenizes as a bare '`' — never code here.
                self::assertNotSame('`', $token, 'SafeArithmetic must not use shell backticks');
                continue;
            }
            self::assertNotSame(T_EVAL, $token[0], 'SafeArithmetic must never use eval');
            // Only real identifiers count — comments and string literals are data, not calls.
            if ($token[0] === T_STRING) {
                self::assertNotContains(strtolower($token[1]), $banned, "SafeArithmetic must not call {$token[1]}");
            }
        }
    }
}
