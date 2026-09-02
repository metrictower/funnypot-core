<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\SeededIndex;
use PHPUnit\Framework\TestCase;

/**
 * SeededIndex::pick is the one place crc32-derived picks become an array offset. Its contract is
 * twofold: (1) on 64-bit PHP it is BYTE-FOR-BYTE `crc32($s) % $count` — every currently-served pick
 * is unchanged on upgrade, no served-byte drift — and (2) it is non-negative and in range on both
 * PHP widths (a raw `crc32() % $count` yields a NEGATIVE offset on 32-bit for ~half of all inputs).
 * The 64-bit equivalence is verified here by execution; the 32-bit correctness follows from the
 * crc32b identity + exact fmod < 2^53 and is documented in the helper (no 32-bit CI runner exists).
 */
final class SeededIndexTest extends TestCase
{
    /** On this (64-bit) runner, pick() must equal crc32($s) % $count for a large corpus × many counts. */
    public function test_matches_crc32_modulo_on_64bit(): void
    {
        if (PHP_INT_SIZE < 8) {
            self::markTestSkipped('64-bit equivalence pin is meaningful only on a 64-bit runner.');
        }

        $counts = [1, 2, 3, 5, 7, 16, 255, 1000];
        for ($i = 0; $i < 1500; $i++) {
            $s = 'seed' . $i . '|pick|' . md5((string) $i);
            foreach ($counts as $count) {
                self::assertSame(
                    crc32($s) % $count,
                    SeededIndex::pick($s, $count),
                    "mismatch for s={$s} count={$count}"
                );
            }
        }
    }

    /** Always a non-negative offset strictly inside [0, count) — the property a raw 32-bit crc32 breaks. */
    public function test_index_is_always_in_range(): void
    {
        foreach (['abc', 'a-negative-crc-input', '9|pick|x', str_repeat('z', 64)] as $s) {
            foreach ([1, 2, 3, 7, 16, 255] as $count) {
                $idx = SeededIndex::pick($s, $count);
                self::assertGreaterThanOrEqual(0, $idx, "s={$s} count={$count}");
                self::assertLessThan($count, $idx, "s={$s} count={$count}");
            }
        }
    }

    /** Degenerate counts return 0 (an empty/one-element list has no other valid offset). */
    public function test_non_positive_count_returns_zero(): void
    {
        self::assertSame(0, SeededIndex::pick('anything', 0));
        self::assertSame(0, SeededIndex::pick('anything', -5));
    }

    /** hexdec(crc32b) is the unsigned form of crc32 — the identity the 32-bit correctness rests on. */
    public function test_crc32b_identity(): void
    {
        foreach (['abc', '', 'the quick brown fox', '0|pick|red,green,blue'] as $s) {
            self::assertSame(crc32($s), (int) hexdec(hash('crc32b', $s)), "identity broke for '{$s}'");
        }
    }
}
