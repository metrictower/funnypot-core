<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\SafeComparison;
use PHPUnit\Framework\TestCase;

/**
 * FP-0436 Phase 1: a CHARACTERIZATION test that pins SafeComparison's current comment/operand
 * truth-table. SafeComparison (FP-0429/0585) is the SHIPPED second comment-folder, consumed by
 * TemplateAttackEmulator + ParamRouteCompiler for the 20-sqli differential decoy. The new SqlLexer is
 * the single canonicalizer and MUST reproduce these exact MySQL comment semantics; a later
 * FP-0426/SafeComparison delegation to the lexer must preserve them too. This test is the regression
 * net: it fails if either the lexer refactor OR a SafeComparison edit changes the observable truth-table.
 *
 * These are OBSERVED current outputs of SafeComparison::evaluate() (not aspirational) — the point of a
 * characterization test is to lock in what the code does today before anything delegates to the lexer.
 */
final class SafeComparisonCharacterizationTest extends TestCase
{
    /**
     * @return array<string,array{0:string,1:bool|null}>
     */
    public function truthTable(): array
    {
        return [
            // Baseline comparisons.
            'eq-true' => ['1=1', true],
            'eq-false' => ['1=2', false],
            'gt-true' => ['2>1', true],
            'gt-false' => ['1>2', false],
            'no-comparison' => ['abc', null],

            // `--` is a line comment ONLY when followed by whitespace/EOL (MySQL rule). So `10--5` is
            // arithmetic 10-(-5)=15, NOT a comment — a naive lexer that treats every `--` as a comment
            // would BREAK this (SafeComparison.php stripSqlComments: `--(?=\s|$)`).
            'double-dash-no-ws-is-arithmetic' => ['10--5 = 15', true],
            // `--` followed by whitespace IS a line comment: `10 -- 5` strips to `10`, no comparison left.
            'double-dash-ws-is-comment' => ['10 -- 5', null],
            // `#` is always a line comment to EOL: `1=1#and 2=2` -> `1=1`.
            'hash-is-comment' => ['1=1#and 2=2', true],

            // Versioned conditional comment /*!NNNNN body*/ is UNWRAPPED (MySQL executes the body), so a
            // sqlmap `versionedkeywords` tamper that hides the operator still splits: `1/*!50000 = */1`
            // -> `1 = 1` -> true.
            'versioned-comment-unwrapped' => ['1/*!50000 = */1', true],
            // Plain inline block comment is inert -> folded to whitespace: `1/* x */= 1` -> `1 = 1`.
            'plain-block-comment-stripped' => ['1/* x */= 1', true],

            // Chained boolean operators: SafeComparison ABSTAINS (returns null) rather than guess a
            // precedence — the evaluator anchors on leading static operands and refuses a chained AND/OR.
            // The lexer's tautology production must likewise not collapse a chained expression to a bool.
            'chained-and-abstains' => ['1=1 and 2=2', null],
            'chained-or-abstains' => ['1=1 or 1=2', null],
        ];
    }

    /**
     * @dataProvider truthTable
     */
    public function test_evaluate_truth_table_is_pinned(string $expr, ?bool $expected): void
    {
        self::assertSame(
            $expected,
            SafeComparison::evaluate($expr),
            "SafeComparison::evaluate('{$expr}') truth-table drifted — the SqlLexer/SafeComparison "
            . 'comment + operand semantics are a shared contract (FP-0436); reconcile before changing.'
        );
    }

    /**
     * The O(n^2)-ReDoS pre-gate (FP-0585): an over-long raw expression is rejected (null) BEFORE the
     * stripSqlComments regexes run. The lexer must likewise bound its input (char-scan, no backtracking).
     */
    public function test_oversized_raw_expression_is_rejected_before_regex(): void
    {
        $bomb = str_repeat('/*', 2000) . '1=1'; // unterminated-comment bomb, > MAX_RAW_LEN
        self::assertNull(SafeComparison::evaluate($bomb), 'oversized raw input must short-circuit to null');
    }
}
