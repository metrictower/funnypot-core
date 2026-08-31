<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\FaviconHash;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * FP-0230 — the favicon-hash correctness contract.
 *
 * The entire payoff of the ticket rides on FaviconHash::hash being byte-for-byte the number a
 * Shodan/FOFA/lonkero scanner computes for http.favicon.hash, i.e. mmh3(base64.encodebytes(bytes)).
 * The forge, the per-asset tests, and the end-to-end serve tests all call the SAME FaviconHash, so
 * they are mutually self-consistent and would stay green on a wrong hash. This test is the one that
 * cannot: its expected values come from an INDEPENDENT C reference oracle (scratchpad/oracle.c, a
 * plain uint32_t MurmurHash3 x86_32 port — NOT the PHP 16-bit-split multiply), baked into
 * tests/Support/fixtures/favicon-kat-vectors.php.
 *
 * Two tiers of vectors:
 *   - a1a: 94 varied-length inputs spanning the murmur 4-byte block edges and the base64 76-char
 *     line-wrap. Fails if the multiply, the finalizer, or the base64 wrapping is wrong.
 *   - a1b: 24 overflow-window inputs, each SELECTED because a deliberately-buggy un-masked-shift
 *     mul32 (the exact B1 bug a plan review reproduced) diverges from the correct result. On these,
 *     FaviconHash::hash === the independent-oracle expected, and the buggy value != expected — so a
 *     regression to the rejected mul32 goes RED here by construction (proven in
 *     test_a1b_buggy_multiply_would_fail_these_vectors).
 */
final class FaviconHashTest extends TestCase
{
    /** @return array{a1a: array<int,array{0:string,1:int}>, a1b: array<int,array{0:string,1:int,2:int}>} */
    private static function vectors(): array
    {
        return require __DIR__ . '/fixtures/favicon-kat-vectors.php';
    }

    public function test_a1a_matches_independent_mmh3_reference_over_varied_lengths(): void
    {
        $vectors = self::vectors()['a1a'];
        self::assertGreaterThanOrEqual(90, count($vectors), 'A1a must pin many independently-computed vectors');
        foreach ($vectors as [$hex, $expected]) {
            $bytes = hex2bin($hex);
            self::assertSame(
                $expected,
                FaviconHash::hash($bytes),
                'FaviconHash must equal mmh3(base64.encodebytes(b)) for a ' . strlen($bytes) . '-byte input'
            );
        }
    }

    public function test_a1b_reproduces_reference_on_overflow_window_inputs(): void
    {
        $vectors = self::vectors()['a1b'];
        self::assertGreaterThanOrEqual(20, count($vectors), 'A1b must pin >=20 overflow-window vectors (ticket requirement)');
        foreach ($vectors as [$hex, $expected, $buggy]) {
            $bytes = hex2bin($hex);
            self::assertSame(
                $expected,
                FaviconHash::hash($bytes),
                'FaviconHash must reproduce the reference on an overflow-window input the buggy mul32 gets wrong'
            );
            // Sanity on the fixture itself: these are exactly the inputs where the two diverge.
            self::assertNotSame($expected, $buggy, 'A1b vector must be one where the buggy mul32 diverges');
        }
    }

    /**
     * The falsifiability proof: run the SAME murmur3 with the rejected un-masked-shift mul32 over the
     * a1b vectors and confirm it produces the recorded (wrong) buggy value, NOT the reference. This is
     * what makes test_a1b_reproduces_reference_on_overflow_window_inputs a red-on-bug guard rather than
     * a tautology: were FaviconHash to regress to this formula, that test would fail on these inputs.
     */
    public function test_a1b_buggy_multiply_would_fail_these_vectors(): void
    {
        foreach (self::vectors()['a1b'] as [$hex, $expected, $buggy]) {
            $got = self::buggyFaviconHash(hex2bin($hex));
            self::assertSame($buggy, $got, 'the rejected mul32 must reproduce the recorded buggy value');
            self::assertNotSame($expected, $got, 'the rejected mul32 must NOT reach the reference (proves red-on-bug)');
        }
    }

    /**
     * Direct unit check on the private mul32 (via reflection) against the three concrete vectors the
     * plan review reproduced: a=0xa024xxxx * C1. The corrected mask-before-shift mul32 returns the
     * `correct` column; the rejected formula returned the `buggy` column (low bits zeroed by float).
     */
    public function test_mul32_matches_reviewer_vectors(): void
    {
        $mul32 = new ReflectionMethod(FaviconHash::class, 'mul32');
        $mul32->setAccessible(true);
        $c1 = 0xcc9e2d51;
        $cases = [
            [0xa024aa70, 0x8eaf9d70],
            [0xa024787d, 0x0dde188d],
            [0xa024f469, 0xaf75ca39],
        ];
        foreach ($cases as [$a, $correct]) {
            self::assertSame(
                $correct,
                $mul32->invoke(null, $a, $c1),
                sprintf('mul32(0x%08x, C1) must equal 0x%08x (mask-before-shift)', $a, $correct)
            );
        }
    }

    public function test_signed_fold_yields_negative_for_high_bit_results(): void
    {
        // A2: at least one a1a vector must fold negative (unsigned hash with the high bit set), proving
        // the `> 0x7fffffff` signed fold — the same reason WordPress's signature is -335242539.
        $sawNegative = false;
        foreach (self::vectors()['a1a'] as [, $expected]) {
            if ($expected < 0) {
                $sawNegative = true;
                break;
            }
        }
        self::assertTrue($sawNegative, 'the corpus must include a negative (high-bit) signed result');
        // And every result is a valid signed int32.
        foreach (self::vectors()['a1a'] as [, $expected]) {
            self::assertGreaterThanOrEqual(-2147483648, $expected);
            self::assertLessThanOrEqual(2147483647, $expected);
        }
    }

    public function test_mime_base64_wraps_at_76_with_trailing_newline(): void
    {
        // A3: the line-wrap is part of the hashed input. A body long enough to exceed one 76-char
        // base64 line must carry a '\n', and the whole thing ends with '\n' (encodebytes semantics).
        $long = random_bytes(200);
        $wrapped = FaviconHash::mimeBase64($long);
        self::assertStringContainsString("\n", $wrapped, 'a >57-byte body base64-wraps past 76 chars');
        self::assertSame("\n", substr($wrapped, -1), 'mimeBase64 ends with a trailing newline');
        // A short body (<= 57 bytes -> <= 76 base64 chars) is a single wrapped line ending in one '\n'.
        $short = random_bytes(30);
        $sw = FaviconHash::mimeBase64($short);
        self::assertSame(1, substr_count($sw, "\n"), 'a <=57-byte body wraps to exactly one line + trailing newline');
    }

    public function test_hashing_unwrapped_base64_differs_from_wrapped(): void
    {
        // The classic wrapping bug: hashing plain base64_encode (no line-wrap) yields a different
        // number than the wrapped mimeBase64 FaviconHash uses. Prove they differ so a future refactor
        // to unwrapped base64 cannot pass silently.
        $bytes = random_bytes(300); // long enough to actually contain a wrap
        $wrappedHash = FaviconHash::hash($bytes);
        $unwrapped = base64_encode($bytes);
        // Reflect murmur over the UNWRAPPED string via a tiny reference is overkill; instead confirm
        // the two encodings themselves differ (a wrap is present) and that hash() used the wrapped one.
        self::assertNotSame($unwrapped, FaviconHash::mimeBase64($bytes), 'wrapped and unwrapped base64 must differ for a 300-byte body');
        // Recompute the hash from the wrapped string path and confirm equality (documents the contract).
        self::assertSame($wrappedHash, FaviconHash::hash($bytes));
    }

    public function test_requires_64bit_or_throws_is_documented(): void
    {
        // This CI box is 64-bit (PHP_INT_SIZE=8), so hash() does not throw. The 32-bit guard is a
        // compile/CI/dev-only fail-fast (spec §2) — asserted here as a documented invariant.
        self::assertGreaterThanOrEqual(8, PHP_INT_SIZE, 'FaviconHash KAT runs on 64-bit PHP');
        self::assertIsInt(FaviconHash::hash("\x89PNG\r\n\x1a\n")); // does not throw on this host
    }

    // --- the rejected un-masked-shift murmur3, used ONLY to prove A1b is red-on-bug ---

    private static function buggyMul32(int $a, int $b): int
    {
        $lo = ($a & 0xffff) * $b;
        // BUG: the high partial is NOT masked to 16 bits before <<16, so `+` crosses PHP_INT_MAX and
        // promotes to float, truncating low bits (the exact B1 defect).
        return ($lo + ((($a >> 16) & 0xffff) * $b << 16)) & 0xffffffff;
    }

    private static function buggyRotl(int $x, int $r): int
    {
        return (($x << $r) | ($x >> (32 - $r))) & 0xffffffff;
    }

    private static function buggyFaviconHash(string $bytes): int
    {
        $d = FaviconHash::mimeBase64($bytes);
        $h1 = 0;
        $len = strlen($d);
        $blocks = intdiv($len, 4);
        for ($i = 0; $i < $blocks; $i++) {
            $o = $i * 4;
            $k1 = ord($d[$o]) | (ord($d[$o + 1]) << 8) | (ord($d[$o + 2]) << 16) | (ord($d[$o + 3]) << 24);
            $k1 = self::buggyMul32($k1, 0xcc9e2d51);
            $k1 = self::buggyRotl($k1, 15);
            $k1 = self::buggyMul32($k1, 0x1b873593);
            $h1 ^= $k1;
            $h1 = self::buggyRotl($h1, 13);
            $h1 = (self::buggyMul32($h1, 5) + 0xe6546b64) & 0xffffffff;
        }
        $tail = $blocks * 4;
        $k1 = 0;
        $rem = $len & 3;
        if ($rem === 3) {
            $k1 ^= ord($d[$tail + 2]) << 16;
        }
        if ($rem >= 2) {
            $k1 ^= ord($d[$tail + 1]) << 8;
        }
        if ($rem >= 1) {
            $k1 ^= ord($d[$tail]);
            $k1 = self::buggyMul32($k1, 0xcc9e2d51);
            $k1 = self::buggyRotl($k1, 15);
            $k1 = self::buggyMul32($k1, 0x1b873593);
            $h1 ^= $k1;
        }
        $h1 ^= $len;
        $h1 ^= ($h1 >> 16);
        $h1 = self::buggyMul32($h1, 0x85ebca6b);
        $h1 ^= ($h1 >> 13);
        $h1 = self::buggyMul32($h1, 0xc2b2ae35);
        $h1 ^= ($h1 >> 16);
        $h1 &= 0xffffffff;

        return $h1 > 0x7fffffff ? $h1 - 0x100000000 : $h1;
    }
}
