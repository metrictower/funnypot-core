<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * FP-0429 — a zero-execution evaluator for the boolean comparison clauses a behavioural SQLi scanner uses
 * to confirm injection by a content differential: `A > B`, `A <= B`, `A (NOT) BETWEEN X AND Y`,
 * `A (NOT) IN (n, …)`. It evaluates ONLY static integer/arithmetic operands — each operand is handed to
 * the existing Support\SafeArithmetic (which this class does NOT modify), so the arithmetic grammar the
 * SSTI/expr-eval oracles depend on is untouched.
 *
 * Returns the comparison's truth, or NULL (INDETERMINATE) whenever ANY operand is not a static literal/
 * arithmetic expression (a column or function operand like ORD(MID(...)) → SafeArithmetic null → null here)
 * or the clause is malformed / over-bound. The differential decoy treats null as "serve the baseline" —
 * so a function-side extraction probe, and any benign non-numeric text, degrade safely to the baseline and
 * are never routed to the FALSE (empty) response. No eval / create_function / `/e` / callback.
 */
final class SafeComparison
{
    /** Max raw clause length (a comparison clause is short; longer = not a scanner probe). */
    private const MAX_LEN = 160;

    /** Max elements in an IN(...) list. */
    private const MAX_IN = 64;

    /** Allowed bytes: digits, arithmetic + parens/space, comparison operators, and keyword letters. */
    private const WHITELIST = '~^[0-9+\-*/%()\s<>=!A-Za-z,]+$~';

    /**
     * Evaluate a comparison clause to its boolean truth, or null when indeterminate/unsafe.
     */
    public static function evaluate(string $expr): ?bool
    {
        $expr = trim($expr);
        $len = strlen($expr);
        if ($len === 0 || $len > self::MAX_LEN) {
            return null;
        }
        if (preg_match(self::WHITELIST, $expr) !== 1) {
            return null;
        }

        // 1) A (NOT) BETWEEN X AND Y
        if (preg_match('~^(?P<a>.+?)\s+(?P<not>not\s+)?between\s+(?P<x>.+?)\s+and\s+(?P<y>.+)$~i', $expr, $m) === 1) {
            $a = self::num($m['a']);
            $x = self::num($m['x']);
            $y = self::num($m['y']);
            if ($a === null || $x === null || $y === null) {
                return null;
            }
            $in = ($a >= $x && $a <= $y);

            return ($m['not'] ?? '') !== '' ? !$in : $in;
        }

        // 2) A (NOT) IN ( n, n, … )
        if (preg_match('~^(?P<a>.+?)\s+(?P<not>not\s+)?in\s*\((?P<list>[^()]*)\)$~i', $expr, $m) === 1) {
            $a = self::num($m['a']);
            if ($a === null) {
                return null;
            }
            $parts = array_map('trim', explode(',', $m['list']));
            if (count($parts) > self::MAX_IN) {
                return null;
            }
            $member = false;
            foreach ($parts as $part) {
                $n = self::num($part);
                if ($n === null) {
                    return null; // a non-literal list element ⇒ indeterminate
                }
                if ($n === $a) {
                    $member = true;
                }
            }

            return ($m['not'] ?? '') !== '' ? !$member : $member;
        }

        // 3) A <op> B  (longest operators first)
        if (preg_match('~^(?P<a>.+?)\s*(?P<op><=|>=|<>|!=|<|>|=)\s*(?P<b>.+)$~', $expr, $m) === 1) {
            $a = self::num($m['a']);
            $b = self::num($m['b']);
            if ($a === null || $b === null) {
                return null;
            }
            switch ($m['op']) {
                case '<':  return $a < $b;
                case '>':  return $a > $b;
                case '<=': return $a <= $b;
                case '>=': return $a >= $b;
                case '=':  return $a === $b;
                case '!=':
                case '<>': return $a !== $b;
            }
        }

        return null;
    }

    /** A static integer / arithmetic operand via SafeArithmetic (which handles sign + + - * / %), else null. */
    private static function num(string $operand): ?int
    {
        $operand = trim($operand);
        if ($operand === '' || preg_match('~^[0-9+\-*/%()\s]+$~', $operand) !== 1) {
            return null; // a column/function/keyword operand is indeterminate
        }

        return SafeArithmetic::evaluate($operand);
    }
}
