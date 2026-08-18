<?php

declare(strict_types=1);

namespace Funnypot\Support;

/**
 * Picks ONE persona bundle for a route, deterministically from a seed string.
 *
 * Same seed ⇒ same bundle every time, so a re-scan by the same attacker is
 * byte-identical and the host never contradicts itself. There is deliberately NO
 * time term (an hourly rotation would make the host appear to change vulnerabilities
 * mid-scan). Different seeds spread the scanner population across personas.
 *
 * Selection is weighted by each bundle's `'w'` (popularity tier): a capped host serves
 * prominent products more often than obscure ones, so the *aggregate* distribution of
 * personas across the scanner population is least-anomalous. Bundles without a `'w'`
 * (the Phase-1 fixture, every uncapped key) weigh 1 — identical to plain uniform
 * `crc32(seed) % count`, preserving prior behaviour exactly.
 */
final class PersonaSelector
{
    /**
     * @param array<int,mixed> $bundles
     * @return array<string,mixed>|null
     */
    public static function pick(array $bundles, string $seed): ?array
    {
        $count = count($bundles);
        if ($count === 0) {
            return null;
        }
        if ($count === 1) {
            return $bundles[0];
        }

        $weights = [];
        $sum = 0;
        foreach ($bundles as $bundle) {
            $w = (int) ($bundle['w'] ?? 1);
            if ($w < 1) {
                $w = 1;
            }
            $weights[] = $w;
            $sum += $w;
        }

        // crc32 is a stable, dependency-free hash; modulo maps it into the weight range.
        // Walk the cumulative weights so a heavier bundle owns a wider slice.
        $target = crc32($seed) % $sum;
        $acc = 0;
        foreach ($bundles as $i => $bundle) {
            $acc += $weights[$i];
            if ($target < $acc) {
                return $bundle;
            }
        }

        return $bundles[$count - 1]; // unreachable: target < sum
    }
}
