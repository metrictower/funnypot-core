<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Waf\Lexer\SqlLexer;
use Funnypot\Core\Waf\Lexer\SqlToken;
use Funnypot\Core\Waf\SqlTokenStreamValidator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0436 Phase 1: unit coverage for the SqlLexer + SqlTokenStreamValidator. Production recognition,
 * the named false-positive firewall shapes, the SafeComparison comment-semantics parity the lexer must
 * reproduce, and fail-safety on adversarial inputs (so Phase 2's pipeline wrapper can rely on "a fault
 * → no match → plain 404", security invariant #2).
 */
final class SqlTokenStreamValidatorTest extends TestCase
{
    private function validator(): SqlTokenStreamValidator
    {
        return new SqlTokenStreamValidator();
    }

    /** @return array<string,array{0:string,1:string}> */
    public function productions(): array
    {
        return [
            'tautology-num' => ['1 OR 1=1', SqlTokenStreamValidator::P_TAUTOLOGY],
            'tautology-str' => ["x OR 'a'='a'", SqlTokenStreamValidator::P_TAUTOLOGY],
            'tautology-and' => ['1 AND 2=2', SqlTokenStreamValidator::P_TAUTOLOGY],
            'tautology-self-ident' => ['1 OR name=name', SqlTokenStreamValidator::P_TAUTOLOGY],
            'union' => ['-1 UNION SELECT 1,2,3', SqlTokenStreamValidator::P_UNION],
            'union-all' => ['-1 UNION ALL SELECT NULL,NULL', SqlTokenStreamValidator::P_UNION],
            'stacked-drop' => ['1;DROP TABLE users', SqlTokenStreamValidator::P_STACKED],
            'stacked-delete' => ['1; DELETE FROM t', SqlTokenStreamValidator::P_STACKED],
            'function-sleep' => ['1 AND SLEEP(5)', SqlTokenStreamValidator::P_FUNCTION],
        ];
    }

    /** @dataProvider productions */
    public function test_productions_classify(string $input, string $expected): void
    {
        self::assertSame($expected, $this->validator()->classify($input));
    }

    /** @return array<string,array{0:string}> The FP firewall shapes that MUST decline (null). */
    public function falsePositiveNegatives(): array
    {
        return [
            'prose-and-or' => ['cats and dogs or small birds'],
            'prose-union-drop' => ['union jack flag'],
            'json-union-catalog' => ['union catalog'],
            'api-field-select' => ['select=name,email'],
            'header-lang' => ['en-US,en;q=0.9'],
            'fpcrs-json-select' => ['select 2024 laptop models'],
            'select-committee' => ['trade union select committee'],
            'note-update' => ['; update the docs'],
            'note-delete' => ['cleanup; delete later'],
            'filter-col-eq-val' => ['status = 1 and type = 2'],
            'bare-union' => ['union'],
            'bare-select' => ['select'],
            'bare-or' => ['or'],
            'reunion-word' => ['planning a family reunion next summer'],
        ];
    }

    /** @dataProvider falsePositiveNegatives */
    public function test_false_positive_shapes_decline(string $input): void
    {
        self::assertNull($this->validator()->classify($input), "must NOT flag benign: {$input}");
    }

    // --- lexer: SafeComparison comment-semantics parity ------------------------------------------

    public function test_double_dash_without_whitespace_is_not_a_comment(): void
    {
        // `10--5` must stay arithmetic (two operators), NOT a line comment — matches SafeComparison.
        $types = $this->typesOf('10--5');
        self::assertSame(
            [SqlToken::T_NUMBER, SqlToken::T_OP, SqlToken::T_OP, SqlToken::T_NUMBER],
            $types
        );
    }

    public function test_double_dash_with_whitespace_is_a_line_comment(): void
    {
        // `10 -- 5` folds the `-- 5` line comment away → only the number remains.
        self::assertSame([SqlToken::T_NUMBER], $this->typesOf('10 -- 5'));
    }

    public function test_hash_is_a_line_comment(): void
    {
        self::assertSame([SqlToken::T_NUMBER], $this->typesOf('42 # the rest is a comment'));
    }

    public function test_plain_block_comment_folds_to_nothing(): void
    {
        self::assertSame([SqlToken::T_NUMBER, SqlToken::T_CMP, SqlToken::T_NUMBER], $this->typesOf('1/* x */=1'));
    }

    public function test_versioned_comment_is_unwrapped_live(): void
    {
        // `/*!50000OR*/` unwraps to a live OR keyword token.
        $types = $this->typesOf('1/*!50000OR*/1=1');
        self::assertContains(SqlToken::T_OR, $types, 'versioned comment body must be tokenised live');
    }

    public function test_reunion_is_one_identifier_not_a_union_keyword(): void
    {
        // intact-boundary invariant: `reunion` is a single T_IDENT, never a T_UNION substring.
        $types = $this->typesOf('reunion');
        self::assertSame([SqlToken::T_IDENT], $types);
    }

    // --- fail-safety / bounds --------------------------------------------------------------------

    public function test_empty_and_whitespace_inputs_are_safe(): void
    {
        self::assertNull($this->validator()->classify(''));
        self::assertNull($this->validator()->classify("   \t\n  "));
    }

    public function test_unterminated_comment_bomb_is_bounded_and_safe(): void
    {
        $bomb = str_repeat('/*', 20000) . 'OR 1=1';
        // No exception, no match (the unterminated `/*` folds the remainder), returns quickly.
        self::assertNull($this->validator()->classify($bomb));
    }

    public function test_oversized_input_is_clipped_not_rejected_with_error(): void
    {
        $big = str_repeat('a ', 50000) . '1 OR 1=1';
        // Bounded to MAX_BYTES; the tail tautology may fall outside the window — the contract is only
        // "no exception, returns a bool-or-null", which Phase 2 relies on for fail-closed behavior.
        $r = $this->validator()->classify($big);
        self::assertTrue($r === null || is_string($r));
    }

    public function test_token_count_is_bounded(): void
    {
        $many = str_repeat('a,', 10000);
        $tokens = (new SqlLexer())->tokenize($many);
        self::assertLessThanOrEqual(SqlLexer::MAX_TOKENS, count($tokens));
    }

    public function test_deeply_nested_versioned_comments_do_not_recurse_unbounded(): void
    {
        $nested = str_repeat('/*!', 5000) . '1=1' . str_repeat('*/', 5000);
        self::assertNull($this->validator()->classify('1 OR ' . $nested) ?: null);
        $this->addToAssertionCount(1); // reached here without stack overflow / timeout
    }

    /** @return int[] the token type ids for $s */
    private function typesOf(string $s): array
    {
        $types = [];
        foreach ((new SqlLexer())->tokenize($s) as $tok) {
            $types[] = $tok['t'];
        }

        return $types;
    }
}
