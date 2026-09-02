<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * A deterministic, width-safe index from a seed string — the one place `crc32()`-derived picks
 * are turned into an array offset.
 *
 * The engine pins `"php": ">=7.3"`, so 32-bit PHP is in-support. There `crc32()` returns a NEGATIVE
 * int for any CRC >= 2^31 (roughly half of all inputs), and `crc32($s) % $count` then yields a
 * negative offset — an undefined array key (a silently dropped directive), or, in a `: string`-typed
 * `pick()` under strict_types, a `null` return that throws a TypeError (a 500). This helper removes
 * that whole failure class.
 *
 * `hexdec(hash('crc32b', $s))` is the SAME value as `crc32($s)`, but always as a non-negative float
 * < 2^32 (verified: `crc32('abc') === (int) hexdec(hash('crc32b','abc'))` on 64-bit). `fmod` is exact
 * for integers < 2^53, so both PHP widths compute the IDENTICAL index. On 64-bit — every currently
 * served pick — the result is BYTE-FOR-BYTE what `crc32($s) % $count` produces today (there is no
 * served-byte drift on upgrade); on 32-bit it is corrected to agree with 64-bit instead of wrapping
 * negative. This is deliberately NOT the naive `& 0x7fffffff` mask, which would change the index for
 * every input whose CRC >= 2^31 — re-rolling ~half of all non-power-of-two picks fleet-wide at
 * upgrade (a simultaneous-churn correlation event) for zero 64-bit correctness gain.
 */
final class SeededIndex
{
    private function __construct()
    {
    }

    /**
     * A stable offset in [0, $count) derived from $material. Returns 0 for a non-positive count so a
     * caller can index an empty/degenerate list without a negative or out-of-range key.
     */
    public static function pick(string $material, int $count): int
    {
        if ($count < 1) {
            return 0;
        }

        return (int) fmod((float) hexdec(hash('crc32b', $material)), (float) $count);
    }
}
