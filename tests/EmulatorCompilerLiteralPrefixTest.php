<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Unit-level guard on the pre-filter literal extractor's core invariant: any `lit` it emits for a
 * rule must be a NECESSARY substring — present in every string the rule's regex matches. If that
 * ever fails, the runtime pre-filter can skip a rule for a request the regex actually matches,
 * silently shadowing it. (AttackLiteralPrefilterTest differential-tests only the 35 shipped rules,
 * so it cannot catch a whole class of extractor bug that no shipped rule happens to exercise.)
 *
 * The necessity check is direct: for a crafted regex, take a string S the regex matches; if a `lit`
 * is emitted, assert stripos(S, lit) !== false. The extractor is conservative, so emitting NO lit
 * is always safe and also passes.
 */
final class EmulatorCompilerLiteralPrefixTest extends TestCase
{
    /** The exact literal the compiler would put in a rule's `lit`, or null when none is emitted. */
    private function emittedLit(string $regex): ?string
    {
        $compiler = new EmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'requiredLiteral');
        $method->setAccessible(true);
        /** @var array{lit:string,in:string,ci:bool}|null $best */
        $best = $method->invoke($compiler, [['in' => 'request', 'regex' => $regex]]);

        return $best === null ? null : $best['lit'];
    }

    /**
     * regex => [regex, a string the regex matches]. A null sample means the regex matches nothing,
     * so the only safe (and asserted) outcome is no lit at all.
     *
     * @return array<string,array{0:string,1:?string}>
     */
    public static function craftedRegexes(): array
    {
        return [
            // Regression: `y{00}` is min-zero, so "xz" (no y) matches — a lit of "xy" would wrongly
            // skip it. The pre-fix extractor emitted "xy" here; this row fails against the old code.
            'multizero-quantifier' => ['xy{00}z', 'xz'],
            // Optional first char: no shared prefix, extractor bails.
            'optional-question'    => ['a?b', 'b'],
            'star'                 => ['a*b', 'b'],
            // Required first char (a{1,}) but single-byte, below the pre-filter length floor.
            'plus'                 => ['a+b', 'ab'],
            // Brace minimums: {0} / {0,2} are optional; {1} / {01} (decimal 01 == 1) are required.
            'brace-zero'           => ['a{0}b', 'b'],
            'brace-zero-comma-two' => ['a{0,2}b', 'b'],
            'brace-one'            => ['a{1}b', 'ab'],
            'brace-leading-zero'   => ['a{01}b', 'ab'],
            // A leading anchor only positions the run; the literal after it is still required.
            'leading-caret'        => ['^abc', 'abc'],
            // Escaped punctuation unescapes to its literal byte and stays in the prefix.
            'escaped-punct'        => ['a\.b', 'a.b'],
            // Escaped alphanumeric is a class/anchor (\d), so it ends the prefix.
            'escaped-alnum'        => ['a\db', 'a5b'],
            // Top-level alternation shares no single prefix across branches — bail.
            'alternation'          => ['ab|cd', 'ab'],
            // A group is a metacharacter boundary; nothing inside it can seed the prefix.
            'nested-group'         => ['(?:ab|cd)ef', 'abef'],
            // A lookahead must never leak its contents into the required prefix.
            'lookahead'            => ['(?=ab)c', null],
        ];
    }

    /**
     * @dataProvider craftedRegexes
     */
    public function test_emitted_lit_is_a_necessary_substring(string $regex, ?string $sample): void
    {
        // Guard the fixture itself: a non-null sample must actually match the regex, or the
        // "necessary substring" claim is meaningless. (ci: matches the extractor's default.)
        if ($sample !== null) {
            self::assertSame(
                1,
                @preg_match('~' . $regex . '~i', $sample),
                "fixture is wrong: sample '{$sample}' does not match /{$regex}/"
            );
        }

        $lit = $this->emittedLit($regex);
        if ($lit === null) {
            // No pre-filter literal — always safe, nothing to shadow.
            $this->addToAssertionCount(1);

            return;
        }

        self::assertNotNull($sample, "a lit '{$lit}' was emitted for /{$regex}/, which matches nothing we can verify against");
        self::assertNotFalse(
            stripos($sample, $lit),
            "lit '{$lit}' is not present in '{$sample}', a string /{$regex}/ matches — the pre-filter would skip a real match"
        );
    }

    /**
     * The regression case, pinned on its own: a multi-zero minimum is optional, so the preceding
     * literal must be dropped and no lit emitted. Fails against the pre-fix `^\{0(?:,\d*)?\}`,
     * which recognised only a single leading zero and so treated `y{00}` as required.
     */
    public function test_multizero_minimum_drops_the_optional_literal(): void
    {
        self::assertNull($this->emittedLit('xy{00}z'), 'y{00} is optional; "xy" must not become a required literal');
        self::assertNull($this->emittedLit('xy{000}z'), 'y{000} is optional');
        self::assertNull($this->emittedLit('xy{00,2}z'), 'y{00,2} is min-zero, so optional');
    }
}
