<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Matcher\RegexWitness;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SubSeed;
use Funnypot\Core\Synthesis\RegexWitnessMenu;
use PHPUnit\Framework\TestCase;

/**
 * FP-0280 — the deterministic regex-witness menu generator (RegexWitness::generateMenu) and the
 * render-time selector (Synthesis\RegexWitnessMenu). The generator turns each variable choice point
 * into a pool; variant zero always draws option zero, so the canonical is byte-identical to the
 * historical generate(). The selector picks a per-deploy vector keyed on the canonical.
 */
final class RegexWitnessMenuTest extends TestCase
{
    // --- byte-identity: canonical == generate() ---------------------------------------------------

    /**
     * @dataProvider representativePatterns
     */
    public function test_canonical_is_byte_identical_to_generate(string $core): void
    {
        $menu = RegexWitness::generateMenu($core, RegexWitness::MENU_K);
        self::assertNotSame([], $menu, "expected a menu for {$core}");
        self::assertSame(RegexWitness::generate($core), $menu[0], "generateMenu()[0] must equal generate() for {$core}");
    }

    /** @return array<int,array{0:string}> */
    public function representativePatterns(): array
    {
        return array_map(static function (string $p): array {
            return [$p];
        }, [
            'abc', 'a|bb|ccc', '[a-z]+', '[^0-9]', '\d\d\d', '\w+', 'col(o|ou)r',
            'x?y*z+', 'token=[0-9]{3}', 'id-[A-F0-9]{4}', 'foo.bar', '(?:ab|cd)ef',
            '[abc]{2,5}', 'sess[a-f0-9]{2,}',
        ]);
    }

    // --- exact choice-stream fixtures (pin the artifact contract) ---------------------------------

    /**
     * The exact menu each core produces. A change to the choice stream is an artifact migration and
     * must fail HERE, not silently reshuffle the compiled index.
     *
     * @dataProvider exactMenus
     * @param list<string> $expected
     */
    public function test_exact_menu_stream(string $core, array $expected): void
    {
        self::assertSame($expected, RegexWitness::generateMenu($core, RegexWitness::MENU_K));
    }

    /** @return array<string,array{0:string,1:list<string>}> */
    public function exactMenus(): array
    {
        return [
            'literal (no choice)'   => ['abc', ['abc']],
            'top-level alternation' => ['a|bb|ccc', ['a', 'ccc', 'bb']],
            'positive class + plus' => ['[a-z]+', ['a', 'zzz', 'zz', 'aaa']],
            'negated class'         => ['[^0-9]', ['a', 'W', 'X', 'c']],
            'digit escapes'         => ['\d\d\d', ['000', '384', '005', '428']],
            'group alternation'     => ['col(o|ou)r', ['color', 'colour']],
            'optional/star/plus'    => ['x?y*z+', ['xyz', 'xyyzz', 'yz', 'yyzzz']],
            'bounded braces'        => ['token=[0-9]{3}', ['token=000', 'token=999', 'token=444']],
            'noncapturing group'    => ['(?:ab|cd)ef', ['abef', 'cdef']],
            'class + brace range'   => ['[abc]{2,5}', ['aa', 'ccc', 'bb', 'cccc']],
        ];
    }

    // --- generator invariants ---------------------------------------------------------------------

    public function test_alternates_are_distinct_nonempty_and_not_canonical(): void
    {
        $menu = RegexWitness::generateMenu('[a-z]{2,4}', RegexWitness::MENU_K);
        $canonical = $menu[0];
        $alternates = array_slice($menu, 1);
        self::assertSame($alternates, array_values(array_unique($alternates)), 'alternates must be distinct');
        foreach ($alternates as $alt) {
            self::assertNotSame('', $alt, 'no empty alternate');
            self::assertNotSame($canonical, $alt, 'no canonical-equal alternate');
        }
    }

    public function test_menu_is_capped_and_deterministic(): void
    {
        self::assertLessThanOrEqual(RegexWitness::MENU_K, count(RegexWitness::generateMenu('[a-z]+', 99)));
        self::assertCount(2, RegexWitness::generateMenu('[a-z]+', 2), 'k is clamped and honoured');
        self::assertSame(
            RegexWitness::generateMenu('token=[0-9]{3}', 4),
            RegexWitness::generateMenu('token=[0-9]{3}', 4),
            'generation is a pure function of (core, k)'
        );
    }

    public function test_no_choice_pattern_returns_only_the_canonical(): void
    {
        self::assertSame(['abc'], RegexWitness::generateMenu('abc', 4), 'a literal has no alternates');
    }

    public function test_unwitnessable_or_empty_core_returns_empty_menu(): void
    {
        self::assertSame([], RegexWitness::generateMenu('', 4));
        self::assertSame([], RegexWitness::generateMenu('(?=lookahead)', 4), 'an unsupported construct yields no menu');
    }

    // --- render-time selector: Synthesis\RegexWitnessMenu -----------------------------------------

    /** @return array<string,mixed> a multi-slot bundle: distinct canonicals, three alternates each. */
    private function multiSlotBundle(): array
    {
        $rx = [];
        $rxm = [];
        foreach (['alpha', 'bravo', 'charlie', 'delta', 'echo'] as $n) {
            $rx[] = $n . '-c';
            $rxm[] = [$n . '-x', $n . '-y', $n . '-z'];
        }

        return ['rx' => $rx, 'rxm' => $rxm];
    }

    public function test_selection_is_deploy_deterministic(): void
    {
        $bundle = $this->multiSlotBundle();
        $seed = PersonaIdentity::seedFromMaterial('deploy-x');
        self::assertSame(
            RegexWitnessMenu::pick($bundle, $seed),
            RegexWitnessMenu::pick($bundle, $seed),
            'the same deploy identity always selects the same vector'
        );
    }

    public function test_selection_varies_across_deploys_and_every_slot_moves(): void
    {
        $bundle = $this->multiSlotBundle();
        $vectors = [];
        $perSlot = array_fill(0, count($bundle['rx']), []);
        for ($i = 0; $i < 64; $i++) {
            $vec = RegexWitnessMenu::pick($bundle, PersonaIdentity::seedFromMaterial('id-' . $i));
            $vectors[implode('|', $vec)] = true;
            foreach ($vec as $j => $val) {
                $perSlot[$j][$val] = true;
            }
        }
        self::assertGreaterThanOrEqual(56, count($vectors), 'the aggregate vector must vary widely across deploys');
        foreach ($perSlot as $j => $values) {
            self::assertGreaterThanOrEqual(2, count($values), "slot {$j} must take at least two values across deploys");
        }
    }

    public function test_same_canonical_and_menu_select_the_same_value(): void
    {
        // Two bundles sharing one canonical/menu must select coherently (keyed on the canonical).
        $a = ['rx' => ['shared-c'], 'rxm' => [['shared-x', 'shared-y', 'shared-z']]];
        $b = ['rx' => ['shared-c'], 'rxm' => [['shared-x', 'shared-y', 'shared-z']]];
        for ($i = 0; $i < 8; $i++) {
            $seed = PersonaIdentity::seedFromMaterial('coh-' . $i);
            self::assertSame(RegexWitnessMenu::pick($a, $seed), RegexWitnessMenu::pick($b, $seed));
        }
    }

    public function test_absent_or_malformed_menu_degrades_to_canonical(): void
    {
        $seed = PersonaIdentity::seedFromMaterial('deploy-y');
        self::assertSame(['only-c'], RegexWitnessMenu::pick(['rx' => ['only-c']], $seed), 'no rxm ⇒ canonical');
        self::assertSame(['only-c'], RegexWitnessMenu::pick(['rx' => ['only-c'], 'rxm' => 'garbage'], $seed));
        // A menu whose only alternate equals the canonical offers no real choice.
        self::assertSame(['dup'], RegexWitnessMenu::pick(['rx' => ['dup'], 'rxm' => [['dup', '']]], $seed));
        self::assertSame([], RegexWitnessMenu::pick(['rx' => []], $seed), 'no rx ⇒ empty vector');
    }

    // --- purity: no 64-bit-only SubSeed::int on the selector/generator paths ----------------------

    public function test_selector_and_generator_use_no_subseed_int(): void
    {
        foreach ([
            __DIR__ . '/../src/Synthesis/RegexWitnessMenu.php',
            __DIR__ . '/../src/Compiler/Matcher/RegexWitness.php',
        ] as $file) {
            self::assertStringNotContainsString('SubSeed::int(', (string) file_get_contents($file), "{$file} must not call the 64-bit-only SubSeed::int");
        }
        // The selector reduces with the 32-bit-safe SubSeed::index.
        self::assertStringContainsString('SubSeed::index', (string) file_get_contents(__DIR__ . '/../src/Synthesis/RegexWitnessMenu.php'));
        self::assertTrue(SubSeed::index(1, SubSeed::NS_WITNESS, 'x', 3) >= 0, 'index is a usable reduction');
    }
}
