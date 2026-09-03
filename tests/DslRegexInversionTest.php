<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Matcher\DslInverter;
use PHPUnit\Framework\TestCase;

/**
 * FP-0261: DSL regex() no longer folds its whole AND-block — it routes through the shared
 * RegexWitnessGenerator, producing a re-validated body/header witness (or folding safely).
 *
 * nuclei's helper is `regex(pattern, input)` — pattern FIRST, region SECOND — which is what real corpus
 * templates emit. The inverter kind-sniffs the two args (string literal = pattern; ident = region), so it
 * inverts regardless of which order the args arrive in; the tests below assert nuclei's real order as the
 * primary contract plus one order-independence case.
 */
final class DslRegexInversionTest extends TestCase
{
    private function invert(string $expr): \Funnypot\Core\Compiler\Matcher\MatcherResult
    {
        return (new DslInverter())->invert(['dsl' => [$expr]]);
    }

    public function test_body_regex_produces_a_revalidated_witness(): void
    {
        // nuclei's real order: regex(pattern, input).
        $r = $this->invert('regex("token=[0-9]{3}", body)');
        self::assertTrue($r->ok, 'a witnessable body regex() must invert, not fold');
        self::assertNotEmpty($r->regexWitness, 'a body witness is emitted');
        foreach ($r->regexWitness as $w) {
            self::assertSame(1, preg_match('~token=[0-9]{3}~', $w), "witness must satisfy the pattern: {$w}");
        }
    }

    public function test_argument_order_is_kind_sniffed_not_positional(): void
    {
        // The load-bearing FP-0261 fix: nuclei is regex(pattern, input), but the inverter must not depend
        // on position — the string literal is always the pattern, the ident is always the region. Both
        // orders must invert to an equivalent witness.
        $forward = $this->invert('regex("token=[0-9]{3}", body)');   // pattern, region  (nuclei's order)
        $reverse = $this->invert('regex(body, "token=[0-9]{3}")');   // region, pattern  (defensive)
        self::assertTrue($forward->ok && $reverse->ok, 'both argument orders must invert');
        foreach (array_merge($forward->regexWitness, $reverse->regexWitness) as $w) {
            self::assertSame(1, preg_match('~token=[0-9]{3}~', $w), "witness must satisfy the pattern: {$w}");
        }
    }

    public function test_header_regex_produces_a_header_word_witness(): void
    {
        $r = $this->invert('regex("sessionid=[a-f0-9]{4}", all_headers)');
        self::assertTrue($r->ok, 'a header-safe, anchor-free regex() inverts to a header word');
        self::assertNotEmpty($r->headerWords);
    }

    public function test_regex_no_longer_folds_the_whole_and_block(): void
    {
        // The core FP-0261 win: a regex() term ANDed with another condition used to fold the entire
        // block (dsl-func:regex). Now the block inverts with both constraints present.
        $r = $this->invert('regex("token=[0-9]{3}", body) && contains(body, "admin")');
        self::assertTrue($r->ok, 'the AND-block survives now that regex() witnesses instead of folding');
        self::assertNotEmpty($r->regexWitness);
        self::assertContains('admin', $r->bodyWords);
    }

    public function test_negated_regex_folds_safely(): void
    {
        // Guaranteeing a pattern never appears in a synthesized body is not safe offline → fold OUT.
        $r = $this->invert('!regex("token=[0-9]{3}", body)');
        self::assertFalse($r->ok, 'a negated regex() must fold, never under-constrain');
        self::assertStringContainsString('regex-negative', $r->reason);
    }

    public function test_unwitnessable_regex_folds_without_throwing(): void
    {
        // A pattern the witness engine can't safely realize (here an invalid quantifier range) folds
        // gracefully (ok=false) — it does not throw or emit a bogus witness.
        $r = $this->invert('regex("a{2,1}", body)');
        self::assertFalse($r->ok, 'an unwitnessable pattern folds');
        self::assertSame('regex-unwitnessable', $r->reason);
        self::assertEmpty($r->regexWitness);
    }

    public function test_typed_header_regex_folds(): void
    {
        // A typed-header (block-position) regex witness is not safe offline.
        $r = $this->invert('regex("application/json", content_type)');
        self::assertFalse($r->ok, 'a typed-header regex() folds');
        self::assertStringContainsString('dsl-regex-typed-header', $r->reason);
    }

    public function test_wrong_arity_folds(): void
    {
        // nuclei's regex() is exactly (pattern, input); anything else is not a shape we can invert.
        $r = $this->invert('regex("token=[0-9]{3}")');
        self::assertFalse($r->ok, 'a one-arg regex() folds');
        self::assertStringContainsString('dsl-regex-arity', $r->reason);
    }

    public function test_two_literals_fold_no_region_ident(): void
    {
        // Neither arg is a region ident → we cannot know where to place the witness. Fold, never guess.
        $r = $this->invert('regex("a", "b")');
        self::assertFalse($r->ok, 'two string literals give no region → fold');
        self::assertStringContainsString('dsl-regex-args', $r->reason);
    }
}
