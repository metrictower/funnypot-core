<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use RuntimeException;

/**
 * Shodan/FOFA/lonkero-style favicon hash: MurmurHash3 x86_32, seed 0, over the
 * MIME-base64 (line-wrapped) encoding of the raw icon bytes, emitted as a SIGNED int32.
 *
 * This is the exact number those aggregate fingerprinters compute for `http.favicon.hash`,
 * so a served favicon whose hash equals a known product signature (Jenkins 81586312,
 * WordPress -335242539, …) corroborates the persona the honeypot presents (FP-0230).
 *
 * COMPILE / CI / DEV ONLY. The serve path never calls this — it only base64_decode()s the
 * pre-forged bytes stored at rest. This helper is used by the collision-blob forge, by the
 * per-asset regression tests, and by the differential KAT that pins it to the reference
 * `mmh3(base64.encodebytes(bytes))` scanners actually run.
 *
 * Integer-width contract (spec §2): PHP ints are 64-bit on prod, so the 32-bit state is
 * masked `& 0xffffffff` after every add/xor/rotl, and every 32-bit multiply routes through
 * mul32() — a 16-bit split that masks the HIGH partial to 16 bits BEFORE the `<<16` shift,
 * so no intermediate reaches PHP_INT_MAX and silently promotes to float. hash() asserts a
 * 64-bit host and throws on a 32-bit build rather than ship a silently-wrong number; a
 * 32-bit CI can swap mul32()'s body for the documented GMP fallback (public contract
 * unchanged).
 */
final class FaviconHash
{
    /** MurmurHash3 x86_32 mixing constants. */
    private const C1 = 0xcc9e2d51;
    private const C2 = 0x1b873593;

    /**
     * Python `base64.encodebytes` equivalent: standard base64 with a `\n` after every 76
     * output chars AND a trailing `\n`. chunk_split() inserts the separator after each
     * 76-char run and once more at the end, so it is byte-identical. This wrapping is part
     * of the hashed input — hashing unwrapped base64 (or `\r\n`) yields a different number.
     */
    public static function mimeBase64(string $bytes): string
    {
        return chunk_split(base64_encode($bytes), 76, "\n");
    }

    /**
     * The favicon hash of the raw icon bytes: murmur3_x86_32(mimeBase64(bytes), seed 0),
     * folded to a signed 32-bit int (values > 0x7fffffff wrap negative — this is why
     * WordPress's published signature is -335242539).
     */
    public static function hash(string $iconBytes): int
    {
        if (PHP_INT_SIZE < 8) {
            throw new RuntimeException('FaviconHash requires 64-bit PHP (or a GMP mul32 fallback); the 32-bit-native path cannot compute this multiply without float truncation.');
        }

        $h = self::murmur3(self::mimeBase64($iconBytes), 0);

        // Signed fold: reinterpret the unsigned 32-bit result as a signed int32.
        return $h > 0x7fffffff ? $h - 0x100000000 : $h;
    }

    /**
     * (a * b) mod 2^32 on 64-bit PHP with no float promotion (spec §2 correctness contract).
     *
     * The high partial is masked to 16 bits BEFORE the `<<16` shift — the exact bug a plan
     * review reproduced (an un-masked high partial reaches ~2^47, the shift ~2^63.7, and the
     * following `+` crosses PHP_INT_MAX → float → low bits lost). With the mask, the largest
     * intermediate is 0xffff*0xffffffff ≈ 2^47.99 ≪ PHP_INT_MAX (2^63-1), so every step stays
     * an exact int64.
     *
     * GMP fallback (for a 32-bit CI, public contract unchanged):
     *   return gmp_intval(gmp_and(gmp_mul($a, $b), gmp_init('0xffffffff')));
     */
    private static function mul32(int $a, int $b): int
    {
        $lo = ($a & 0xffff) * $b;              // <= 0xffff * 0xffffffff ~= 2^47.99  (int64-safe)
        $hi = (($a >> 16) & 0xffff) * $b;      // <= 0xffff * 0xffffffff ~= 2^47.99  (int64-safe)

        return ($lo + (($hi & 0xffff) << 16)) & 0xffffffff; // mask the high partial, THEN <<16
    }

    /** 32-bit left rotate on a value already reduced mod 2^32. */
    private static function rotl32(int $x, int $r): int
    {
        return (($x << $r) | ($x >> (32 - $r))) & 0xffffffff;
    }

    /**
     * MurmurHash3 x86_32 (Austin Appleby), returning the UNSIGNED 32-bit result. Every
     * 32-bit multiply routes through mul32(); every add/xor/rotl is masked to 32 bits.
     */
    private static function murmur3(string $data, int $seed = 0): int
    {
        $h1 = $seed & 0xffffffff;
        $len = strlen($data);
        $blocks = intdiv($len, 4);

        for ($i = 0; $i < $blocks; $i++) {
            $o = $i * 4;
            // Little-endian 32-bit block.
            $k1 = ord($data[$o])
                | (ord($data[$o + 1]) << 8)
                | (ord($data[$o + 2]) << 16)
                | (ord($data[$o + 3]) << 24);

            $k1 = self::mul32($k1, self::C1);
            $k1 = self::rotl32($k1, 15);
            $k1 = self::mul32($k1, self::C2);

            $h1 ^= $k1;
            $h1 = self::rotl32($h1, 13);
            $h1 = (self::mul32($h1, 5) + 0xe6546b64) & 0xffffffff;
        }

        // Tail (0..3 trailing bytes).
        $tail = $blocks * 4;
        $k1 = 0;
        $rem = $len & 3;
        if ($rem === 3) {
            $k1 ^= ord($data[$tail + 2]) << 16;
        }
        if ($rem >= 2) {
            $k1 ^= ord($data[$tail + 1]) << 8;
        }
        if ($rem >= 1) {
            $k1 ^= ord($data[$tail]);
            $k1 = self::mul32($k1, self::C1);
            $k1 = self::rotl32($k1, 15);
            $k1 = self::mul32($k1, self::C2);
            $h1 ^= $k1;
        }

        // Finalization.
        $h1 ^= $len;
        $h1 = self::fmix32($h1);

        return $h1;
    }

    /** MurmurHash3 32-bit finalizer (avalanche). */
    private static function fmix32(int $h): int
    {
        $h ^= ($h >> 16);
        $h = self::mul32($h, 0x85ebca6b);
        $h ^= ($h >> 13);
        $h = self::mul32($h, 0xc2b2ae35);
        $h ^= ($h >> 16);

        return $h & 0xffffffff;
    }
}
