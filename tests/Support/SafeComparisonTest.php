<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\SafeComparison;
use PHPUnit\Framework\TestCase;

/**
 * FP-0429: SafeComparison truth table + the INDETERMINATE→null contract (a non-literal operand degrades to
 * null so the differential decoy serves the baseline, never the FALSE page, and never a 5xx).
 */
final class SafeComparisonTest extends TestCase
{
    /** @return array<string,array{0:string,1:?bool}> */
    public function cases(): array
    {
        return [
            // comparisons (incl. longest-operator tokenization + negatives)
            'gt true' => ['2 > 1', true],
            'gt false' => ['1 > 2', false],
            'lt true' => ['1 < 2', true],
            'ge eq' => ['2 >= 2', true],
            'le eq' => ['2 <= 2', true],
            'ge false' => ['1 >= 2', false],
            'ne <>' => ['3 <> 4', true],
            'ne !=' => ['5 != 5', false],
            'eq' => ['7 = 7', true],
            'negative' => ['-3 < -1', true],
            'arith operand' => ['3*2 > (1*5)', true],       // delegates to SafeArithmetic
            'arith operand false' => ['3*3 < 2*4', false],
            // ranges
            'between in' => ['5 BETWEEN 1 AND 9', true],
            'between out' => ['11 BETWEEN 0 AND 9', false],
            'not between true' => ['5 NOT BETWEEN 0 AND 3', true],
            'not between false' => ['2 NOT BETWEEN 0 AND 3', false],
            // sets
            'in true' => ['7 IN (6,7,8)', true],
            'in false' => ['9 IN (6,7,8)', false],
            'not in true' => ['9 NOT IN (6,7,8)', true],
            'not in false' => ['7 NOT IN (6,7,8)', false],
            // INDETERMINATE → null (the benign-safety contract)
            'column operand' => ['ORD(x) > 65', null],
            'func lhs' => ['ascii(substr(a,1,1)) >= 97', null],
            'in with subselect-ish' => ['id IN (col, 7)', null],
            'between non-literal' => ['x BETWEEN 1 AND 9', null],
            'bare word' => ['rating < three', null],
            'empty' => ['', null],
            'malformed' => ['2 >', null],
            'no operator' => ['42', null],
            'over-length' => [str_repeat('9', 200) . '>1', null],
        ];
    }

    /** @dataProvider cases */
    public function test_truth_table(string $expr, ?bool $expected): void
    {
        self::assertSame($expected, SafeComparison::evaluate($expr), $expr);
    }
}
