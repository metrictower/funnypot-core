<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Support\PersonaSelector;
use PHPUnit\Framework\TestCase;

/**
 * Weighted persona selection: deterministic per seed, spread across the population in
 * proportion to weight, and byte-identical to the old uniform pick when no weights are
 * present (the Phase-1 fixture / every uncapped key).
 */
final class PersonaSelectorTest extends TestCase
{
    public function test_deterministic_per_seed(): void
    {
        $bundles = [
            ['pid' => 'a', 'w' => 100],
            ['pid' => 'b', 'w' => 30],
            ['pid' => 'c', 'w' => 2],
        ];

        for ($i = 0; $i < 20; $i++) {
            $seed = "attacker-{$i}";
            self::assertSame(
                PersonaSelector::pick($bundles, $seed),
                PersonaSelector::pick($bundles, $seed),
                'same seed must always pick the same bundle'
            );
        }
    }

    public function test_population_spreads_and_favours_heavier_weights(): void
    {
        $bundles = [
            ['pid' => 'heavy', 'w' => 100],
            ['pid' => 'mid', 'w' => 30],
            ['pid' => 'light', 'w' => 2],
        ];

        $counts = ['heavy' => 0, 'mid' => 0, 'light' => 0];
        for ($i = 0; $i < 2000; $i++) {
            $picked = PersonaSelector::pick($bundles, "seed-{$i}");
            $counts[$picked['pid']]++;
        }

        // Every persona is reachable across the scanner population...
        self::assertGreaterThan(0, $counts['heavy']);
        self::assertGreaterThan(0, $counts['mid']);
        self::assertGreaterThan(0, $counts['light']);
        // ...and the heavier tiers are served more often than the light tail.
        self::assertGreaterThan($counts['mid'], $counts['heavy']);
        self::assertGreaterThan($counts['light'], $counts['mid']);
    }

    public function test_absent_weights_are_uniform_and_match_legacy_pick(): void
    {
        // No 'w' => weight 1 each => the walk reduces to crc32(seed) % count, the exact
        // behaviour before the cap. Verify against that legacy formula for many seeds.
        $bundles = [['pid' => 'a'], ['pid' => 'b'], ['pid' => 'c'], ['pid' => 'd']];
        $count = count($bundles);

        for ($i = 0; $i < 200; $i++) {
            $seed = "s{$i}";
            $legacy = $bundles[crc32($seed) % $count];
            self::assertSame($legacy, PersonaSelector::pick($bundles, $seed));
        }
    }

    public function test_single_and_empty(): void
    {
        self::assertNull(PersonaSelector::pick([], 'x'));
        self::assertSame(['pid' => 'only'], PersonaSelector::pick([['pid' => 'only']], 'x'));
    }
}
