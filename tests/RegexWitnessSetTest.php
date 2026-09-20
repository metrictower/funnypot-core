<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RegexWitnessSet;
use PHPUnit\Framework\TestCase;

/**
 * FP-0280 — the one merge law for canonical/menu witness pairs. Equal canonicals INTERSECT their
 * menus (never keep-first, never concatenate), so one frozen rx slot's alternates satisfy every
 * source pattern that collapsed into it. The cap bounds only NEW canonicals.
 */
final class RegexWitnessSetTest extends TestCase
{
    public function test_distinct_canonicals_keep_their_own_menus_in_order(): void
    {
        [$rx, $rxm] = RegexWitnessSet::merge(
            ['a-c'],
            [['a-x', 'a-y']],
            ['b-c'],
            [['b-x']]
        );
        self::assertSame(['a-c', 'b-c'], $rx);
        self::assertSame([['a-x', 'a-y'], ['b-x']], $rxm);
    }

    public function test_equal_canonical_intersects_menus_in_existing_order(): void
    {
        // The reviewer's pair: root:.*:0:0: and root:[^:]:0:0: collapse to canonical root:a:0:0: but
        // their generated alternates only partly overlap. The merge keeps the intersection, so the
        // frozen slot's alternates satisfy BOTH source patterns.
        [$rx, $rxm] = RegexWitnessSet::merge(
            ['root:a:0:0:'],
            [['root:b:0:0:', 'root:z:0:0:']],
            ['root:a:0:0:'],
            [['root:z:0:0:', 'root:q:0:0:']]
        );
        self::assertSame(['root:a:0:0:'], $rx);
        self::assertSame([['root:z:0:0:']], $rxm, 'only the shared alternate survives, in existing order');
    }

    public function test_missing_or_empty_incoming_menu_empties_the_intersection(): void
    {
        [$rx, $rxm] = RegexWitnessSet::merge(
            ['c'],
            [['x', 'y']],
            ['c'],
            [[]]
        );
        self::assertSame(['c'], $rx);
        self::assertSame([[]], $rxm, 'an empty incoming menu is canonical-only ⇒ empty intersection');
    }

    public function test_empty_canonical_equal_and_duplicate_alternates_are_dropped(): void
    {
        [, $rxm] = RegexWitnessSet::normalize(['c'], [['c', '', 'x', 'x', 'y']]);
        self::assertSame([['x', 'y']], $rxm);
    }

    public function test_cap_bounds_new_canonicals_but_a_later_collision_still_narrows(): void
    {
        [$rx, $rxm] = RegexWitnessSet::merge(
            ['c0', 'c1'],
            [['a', 'b'], ['x']],
            ['c2', 'c0'],
            [['q'], ['b', 'z']],
            2 // cap
        );
        self::assertSame(['c0', 'c1'], $rx, 'the third distinct canonical is dropped by the cap');
        self::assertSame([['b'], ['x']], $rxm, 'the post-cap collision on c0 still intersects its menu');
    }

    public function test_merge_is_idempotent(): void
    {
        $rx = ['c0', 'c1'];
        $rxm = [['x', 'y'], ['z']];
        [$rx2, $rxm2] = RegexWitnessSet::normalize($rx, $rxm);
        [$rx3, $rxm3] = RegexWitnessSet::normalize($rx2, $rxm2);
        self::assertSame($rx2, $rx3);
        self::assertSame($rxm2, $rxm3);
    }

    public function test_output_arrays_are_always_aligned(): void
    {
        [$rx, $rxm] = RegexWitnessSet::merge(['a', 'b', 'c'], [['1'], [], ['2', '3']], ['a', 'd'], [['1', '9'], ['7']]);
        self::assertCount(count($rx), $rxm, 'rx and rxm are equal length at the boundary');
    }
}
