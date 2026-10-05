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
 * A trailing SQL comment (`-- `, `#`) or inline `/* … *\/` the scanner appends to neutralise the host
 * query's tail is stripped first, and the operators are anchored to the LEADING static operands, so a
 * comment-terminated or clause-suffixed probe (`1>2-- -`, `1>2 ORDER BY 1`) still yields its true/false —
 * matching how the equality channel already tolerates such suffixes.
 *
 * Returns the comparison's truth, or NULL (INDETERMINATE) whenever ANY operand is not a static literal/
 * arithmetic expression (a column or function operand like ORD(MID(...)) → SafeArithmetic null → null here),
 * the clause is malformed / over-bound, or it chains a further boolean (`… AND …` / `… OR …`) whose truth
 * we will not guess. The differential decoy treats null as "serve the baseline" — so a function-side
 * extraction probe, and any benign non-numeric text, degrade safely to the baseline and are never routed
 * to the FALSE (empty) response. No eval / create_function / `/e` / callback.
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
        // A boolean-blind scanner terminates almost every injected clause with a trailing SQL comment
        // (`-- -`, `#`) so it neutralises the host query's tail; strip it first, or a FALSE comparison
        // would be left non-parseable → INDETERMINATE → baseline, collapsing the very differential this
        // exists to produce. Done before the whitelist/length checks so a stripped `#…` tail (whose `#`
        // is not whitelisted) does not reject the whole clause.
        $expr = self::stripSqlComments(trim($expr));
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
        if (preg_match('~^(?P<a>.+?)\s+(?P<not>not\s+)?in\s*\((?P<list>[^()]*)\)\s*$~i', $expr, $m) === 1) {
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

        // 3) A <op> B  (longest operators first). The operands are anchored to the LEADING static
        //    arithmetic runs, not to end-of-string, so a trailing non-operand token the scanner appends
        //    (an `ORDER BY`/`LIMIT` clause, a stray paren) does not make the whole clause unparseable —
        //    the bare differential `A op B` is still measured. The only tail we refuse to guess at is a
        //    CHAINED boolean operator (`… AND …` / `… OR …`): its truth depends on a sub-clause we do not
        //    evaluate, so we abstain (null → baseline) rather than risk serving the wrong differential arm.
        if (preg_match('~^(?P<a>[0-9+\-*/%()\s]+?)(?P<op><=|>=|<>|!=|<|>|=)(?P<b>[0-9+\-*/%()\s]+)(?P<tail>.*)$~s', $expr, $m) === 1) {
            if (preg_match('~\b(?:and|or)\b~i', $m['tail']) === 1) {
                return null; // chained boolean logic — abstain to the baseline rather than guess
            }
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

    /**
     * Remove the trailing SQL line comment (`-- ` / `#`) and any inline block comment (`/* … *\/`) a
     * scanner appends to terminate the host query. `--` is only a comment when followed by whitespace or
     * end-of-string (MySQL rule), so a bare `10--5` stays arithmetic. Pure string surgery, no execution.
     *
     * A MySQL VERSIONED conditional comment `/*!NNNNN … *\/` (whose body MySQL actually executes) is
     * stripped as if inert, so a probe that wraps the whole comparison in one degrades safe-direction to
     * the baseline rather than splitting. That is an uncommon tamper and a believability gap, not a safety
     * hole — unwrapping it to keep the inner clause live is tracked separately (see FP-0585).
     */
    private static function stripSqlComments(string $expr): string
    {
        $expr = (string) preg_replace('~/\*.*?\*/~s', ' ', $expr);
        $expr = (string) preg_replace('~\s*(?:--(?=\s|$).*|#.*)$~s', '', $expr);

        return trim($expr);
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
