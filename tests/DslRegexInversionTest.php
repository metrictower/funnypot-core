<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Matcher\DslInverter;
use PHPUnit\Framework\TestCase;

/**
 * FP-0261: DSL regex() no longer folds its whole AND-block — it routes through the shared
 * RegexWitnessGenerator, producing a re-validated body/header witness (or folding safely).
 */
final class DslRegexInversionTest extends TestCase
{
    private function invert(string $expr): \Funnypot\Core\Compiler\Matcher\MatcherResult
    {
        return (new DslInverter())->invert(['dsl' => [$expr]]);
    }

    public function test_body_regex_produces_a_revalidated_witness(): void
    {
        $r = $this->invert('regex(body, "token=[0-9]{3}")');
        self::assertTrue($r->ok, 'a witnessable body regex() must invert, not fold');
        self::assertNotEmpty($r->regexWitness, 'a body witness is emitted');
        foreach ($r->regexWitness as $w) {
            self::assertSame(1, preg_match('~token=[0-9]{3}~', $w), "witness must satisfy the pattern: {$w}");
        }
    }

    public function test_header_regex_produces_a_header_word_witness(): void
    {
        $r = $this->invert('regex(all_headers, "sessionid=[a-f0-9]{4}")');
        self::assertTrue($r->ok, 'a header-safe, anchor-free regex() inverts to a header word');
        self::assertNotEmpty($r->headerWords);
    }

    public function test_regex_no_longer_folds_the_whole_and_block(): void
    {
        // The core FP-0261 win: a regex() term ANDed with another condition used to fold the entire
        // block (dsl-func:regex). Now the block inverts with both constraints present.
        $r = $this->invert('regex(body, "token=[0-9]{3}") && contains(body, "admin")');
        self::assertTrue($r->ok, 'the AND-block survives now that regex() witnesses instead of folding');
        self::assertNotEmpty($r->regexWitness);
        self::assertContains('admin', $r->bodyWords);
    }

    public function test_negated_regex_folds_safely(): void
    {
        // Guaranteeing a pattern never appears in a synthesized body is not safe offline → fold OUT.
        $r = $this->invert('!regex(body, "token=[0-9]{3}")');
        self::assertFalse($r->ok, 'a negated regex() must fold, never under-constrain');
        self::assertStringContainsString('regex-negative', $r->reason);
    }

    public function test_unwitnessable_regex_folds_without_throwing(): void
    {
        // A pattern the witness engine can't safely realize (here an invalid quantifier range) folds
        // gracefully (ok=false) — it does not throw or emit a bogus witness.
        $r = $this->invert('regex(body, "a{2,1}")');
        self::assertFalse($r->ok, 'an unwitnessable pattern folds');
        self::assertSame('regex-unwitnessable', $r->reason);
        self::assertEmpty($r->regexWitness);
    }

    public function test_typed_header_regex_folds(): void
    {
        // A typed-header (block-position) regex witness is not safe offline.
        $r = $this->invert('regex(content_type, "application/json")');
        self::assertFalse($r->ok, 'a typed-header regex() folds');
    }
}
