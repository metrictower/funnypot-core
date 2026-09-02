<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

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

        // A stable, dependency-free hash mapped into the weight range via SeededIndex (unsigned on
        // 32-bit, where a raw crc32() would wrap negative and always select bundle 0 — a silent
        // persona-selection bias). Byte-identical to crc32($seed) % $sum on 64-bit.
        // Walk the cumulative weights so a heavier bundle owns a wider slice.
        $target = SeededIndex::pick($seed, $sum);
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
