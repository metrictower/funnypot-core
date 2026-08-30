<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * A tiny, self-contained integer arithmetic evaluator — the safe engine behind the SSTI decoy.
 * It "renders" a template-injection probe's arithmetic ({{7*7}} -> 49) with NO code execution:
 * never eval / create_function / a `/e` regex / a callback / a real template engine. Just a
 * hand-written recursive-descent parser over a closed grammar.
 *
 * Grammar (integers only):
 *   expr   := term (('+' | '-') term)*
 *   term   := factor (('*' | '/' | '%') factor)*
 *   factor := ('-' | '+') factor | '(' expr ')' | number
 *
 * Safe by construction:
 *  - the input is whitelisted to [0-9 + - * / % ( ) space tab] and length-capped BEFORE parsing,
 *    so a non-arithmetic payload ({{config}}, {{''.__class__}}) is rejected outright;
 *  - all math is integer; every operand and every intermediate result is magnitude-bounded, so the
 *    output is always pure digits (never a float / scientific notation — inert in an HTML/XML sink);
 *  - division or modulo by zero returns null (guarded before the operator runs — never a
 *    warning/exception, so never a 500);
 *  - any grammar / bound / whitespace-only failure returns null, so the caller degrades to its
 *    normal response rather than emitting a partial or non-numeric result.
 */
final class SafeArithmetic
{
    /** Hard magnitude bound for operands and intermediate results (i4 width). */
    public const DEFAULT_MAX = 2147483647;

    /** Default cap on the raw expression length. */
    public const DEFAULT_MAX_LEN = 32;

    /** The only bytes an expression may contain; anything else fails the whole evaluation. */
    private const ALLOWED = "0123456789+-*/%() \t";

    /** @var array<int,array{0:string,1?:int|string}> token stream: num/op/lp/rp */
    private $tokens = [];

    /** @var int cursor into $tokens */
    private $pos = 0;

    /** @var int magnitude bound for operands and results */
    private $max = self::DEFAULT_MAX;

    /** @var bool sticky parse-failure flag; once set, every parse step short-circuits */
    private $failed = false;

    /**
     * Evaluate $expr as an integer, or null on any rejection: a non-arithmetic byte, over the length
     * cap, a malformed grammar, an out-of-bound operand/result, or division/modulo by zero.
     */
    public static function evaluate(string $expr, int $max = self::DEFAULT_MAX, int $maxLen = self::DEFAULT_MAX_LEN): ?int
    {
        if ($max < 1 || $max > self::DEFAULT_MAX) {
            $max = self::DEFAULT_MAX;
        }
        if ($maxLen < 1 || $maxLen > 256) {
            $maxLen = self::DEFAULT_MAX_LEN;
        }
        $len = strlen($expr);
        if ($len === 0 || $len > $maxLen) {
            return null;
        }
        // Whitelist every byte before touching the parser — this is what makes a non-arithmetic
        // SSTI payload ({{config}}, {{''.__class__}}) a hard reject rather than a parse attempt.
        if (strspn($expr, self::ALLOWED) !== $len) {
            return null;
        }

        $self = new self();
        $self->max = $max;
        $tokens = $self->tokenize($expr);
        if ($tokens === null) {
            return null;
        }
        $self->tokens = $tokens;
        $self->pos = 0;

        $value = $self->parseExpr();
        // A grammar error, or leftover tokens (e.g. "1 2", "(1", "1)") -> reject the whole thing.
        if ($self->failed || $self->pos !== count($tokens)) {
            return null;
        }

        return $value;
    }

    /**
     * Split a whitelisted expression into num/op/paren tokens. Numbers accumulate digit-by-digit
     * with a running bound check, so an over-long digit run fails without ever building a float.
     * Returns null on an out-of-bound number literal. (Whitespace is skipped; no other byte can
     * appear here — the caller already whitelisted the string.)
     *
     * @return array<int,array{0:string,1?:int|string}>|null
     */
    private function tokenize(string $expr): ?array
    {
        $tokens = [];
        $len = strlen($expr);
        $i = 0;
        while ($i < $len) {
            $ch = $expr[$i];
            if ($ch === ' ' || $ch === "\t") {
                $i++;
                continue;
            }
            if ($ch >= '0' && $ch <= '9') {
                $value = 0;
                while ($i < $len && $expr[$i] >= '0' && $expr[$i] <= '9') {
                    $value = $value * 10 + (ord($expr[$i]) - 48);
                    if ($value > $this->max) {
                        return null; // operand out of bounds — never widen to float
                    }
                    $i++;
                }
                $tokens[] = ['num', $value];
                continue;
            }
            if ($ch === '(') {
                $tokens[] = ['lp'];
                $i++;
                continue;
            }
            if ($ch === ')') {
                $tokens[] = ['rp'];
                $i++;
                continue;
            }
            // The only remaining whitelisted bytes are the five operators.
            $tokens[] = ['op', $ch];
            $i++;
        }

        return $tokens;
    }

    /** expr := term (('+' | '-') term)* */
    private function parseExpr(): int
    {
        $left = $this->parseTerm();
        while (!$this->failed && $this->peekOp('+', '-')) {
            $op = $this->tokens[$this->pos][1];
            $this->pos++;
            $right = $this->parseTerm();
            if ($this->failed) {
                return 0;
            }
            $left = $this->apply((string) $op, $left, $right);
        }

        return $left;
    }

    /** term := factor (('*' | '/' | '%') factor)* */
    private function parseTerm(): int
    {
        $left = $this->parseFactor();
        while (!$this->failed && $this->peekOp('*', '/', '%')) {
            $op = $this->tokens[$this->pos][1];
            $this->pos++;
            $right = $this->parseFactor();
            if ($this->failed) {
                return 0;
            }
            $left = $this->apply((string) $op, $left, $right);
        }

        return $left;
    }

    /** factor := ('-' | '+') factor | '(' expr ')' | number */
    private function parseFactor(): int
    {
        if ($this->failed || $this->pos >= count($this->tokens)) {
            $this->failed = true;

            return 0;
        }
        $tok = $this->tokens[$this->pos];

        if ($tok[0] === 'op' && ($tok[1] === '-' || $tok[1] === '+')) {
            $this->pos++;
            $value = $this->parseFactor();
            if ($this->failed) {
                return 0;
            }

            return $tok[1] === '-' ? $this->bound(-$value) : $value;
        }
        if ($tok[0] === 'lp') {
            $this->pos++;
            $value = $this->parseExpr();
            if ($this->failed || $this->pos >= count($this->tokens) || $this->tokens[$this->pos][0] !== 'rp') {
                $this->failed = true;

                return 0;
            }
            $this->pos++; // consume ')'

            return $value;
        }
        if ($tok[0] === 'num') {
            $this->pos++;

            return (int) $tok[1];
        }

        $this->failed = true;

        return 0;
    }

    /** True when the current token is an operator matching one of the given characters. */
    private function peekOp(string ...$chars): bool
    {
        if ($this->pos >= count($this->tokens)) {
            return false;
        }
        $tok = $this->tokens[$this->pos];

        return $tok[0] === 'op' && in_array((string) $tok[1], $chars, true);
    }

    /**
     * Apply one closed-set operator to two bounded integers. Division/modulo by zero, an operation
     * that overflows to float (a 32-bit host), or a result past the magnitude bound all set the
     * failure flag and return 0 (ignored) — the whole evaluation then yields null.
     */
    private function apply(string $op, int $a, int $b): int
    {
        if ($op === '+') {
            $r = $a + $b;

            return is_int($r) ? $this->bound($r) : $this->fail();
        }
        if ($op === '-') {
            $r = $a - $b;

            return is_int($r) ? $this->bound($r) : $this->fail();
        }
        if ($op === '*') {
            $r = $a * $b;

            return is_int($r) ? $this->bound($r) : $this->fail();
        }
        if ($op === '/') {
            if ($b === 0) {
                return $this->fail(); // guarded before intdiv -> no exception, no 500
            }

            return $this->bound(intdiv($a, $b));
        }
        // modulo
        if ($b === 0) {
            return $this->fail(); // guarded before % -> no DivisionByZeroError
        }

        return $this->bound($a % $b);
    }

    /** Enforce the magnitude bound; a result outside it fails the evaluation. */
    private function bound(int $v): int
    {
        if ($v < -$this->max || $v > $this->max) {
            return $this->fail();
        }

        return $v;
    }

    /** Mark the parse failed and return a placeholder the caller discards. */
    private function fail(): int
    {
        $this->failed = true;

        return 0;
    }
}
