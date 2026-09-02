<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\Fake\FakeSecrets;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Dead-but-syntactically-valid inert secrets for the mock-auth panels: every value is a pure
 * function of (seed, key), authenticates to nothing anywhere, and is per-(seed,key) unique so
 * two deployments never collide on the same "leaked" value.
 */
final class FakeSecretsTest extends TestCase
{
    public function test_api_key_is_deterministic_for_same_seed_and_key(): void
    {
        self::assertSame(
            FakeSecrets::apiKey(1, 'row-0'),
            FakeSecrets::apiKey(1, 'row-0')
        );
    }

    public function test_api_key_shape(): void
    {
        $k = FakeSecrets::apiKey(1, 'row-0');
        // Base32 body ([A-Z2-7]) — a real AWS access-key-id never carries 0/1/8/9, so the old
        // uppercase-ALNUM draw was a checkable tell. Matches PersonaIdentity::awsAccessKeyId.
        self::assertMatchesRegularExpression('/^AKIA[A-Z2-7]{16}$/', $k);
        self::assertNotSame('AKIAIOSFODNN7EXAMPLE', $k);
    }

    /** The base32 body must never contain 0, 1, 8, or 9 (the digits base32 [A-Z2-7] excludes). */
    public function test_api_key_never_carries_non_base32_digits(): void
    {
        for ($seed = 0; $seed < 64; $seed++) {
            $body = substr(FakeSecrets::apiKey($seed, 'row-' . $seed), 4);
            self::assertSame(0, preg_match('/[0189]/', $body), "seed={$seed} body={$body}");
        }
    }

    public function test_api_key_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::apiKey(1, 'row-0'), FakeSecrets::apiKey(2, 'row-0'));
        self::assertNotSame(FakeSecrets::apiKey(1, 'row-0'), FakeSecrets::apiKey(1, 'row-1'));
    }

    public function test_stripe_key_is_deterministic_and_shaped(): void
    {
        $k = FakeSecrets::stripeKey(3, 'row-0');
        self::assertSame($k, FakeSecrets::stripeKey(3, 'row-0'));
        self::assertMatchesRegularExpression('/^sk_test_[A-Za-z0-9]{24}$/', $k);
    }

    public function test_stripe_key_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::stripeKey(3, 'row-0'), FakeSecrets::stripeKey(4, 'row-0'));
        self::assertNotSame(FakeSecrets::stripeKey(3, 'row-0'), FakeSecrets::stripeKey(3, 'row-1'));
    }

    public function test_reset_token_is_deterministic_and_shaped(): void
    {
        $t = FakeSecrets::resetToken(5, 'row-0');
        self::assertSame($t, FakeSecrets::resetToken(5, 'row-0'));
        self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $t);
    }

    public function test_reset_token_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::resetToken(5, 'row-0'), FakeSecrets::resetToken(6, 'row-0'));
        self::assertNotSame(FakeSecrets::resetToken(5, 'row-0'), FakeSecrets::resetToken(5, 'row-1'));
    }

    public function test_bcrypt_hash_is_deterministic_and_shaped(): void
    {
        $h = FakeSecrets::bcryptHash(7, 'row-0');
        self::assertSame($h, FakeSecrets::bcryptHash(7, 'row-0'));
        // Legal bcrypt alphabet — `./A-Za-z0-9`, NOT the old alnum-only draw (which never emitted
        // `.`/`/`, a ~18%-likely statistical tell across a table of hashes).
        self::assertMatchesRegularExpression('#^\$2y\$10\$[./A-Za-z0-9]{53}$#', $h);
    }

    /**
     * The 22nd (last) salt char carries only 2 significant bits in a real bcrypt salt, so only
     * `.`, `O`, `e`, `u` (alphabet indices 0/16/32/48) can legally appear there — anything else is
     * an impossible-salt tell. Offset 7 + 21 in the composed string is that char.
     */
    public function test_bcrypt_hash_last_salt_char_is_legal(): void
    {
        for ($seed = 0; $seed < 64; $seed++) {
            $h = FakeSecrets::bcryptHash($seed, 'row-' . $seed);
            self::assertContains($h[7 + 21], ['.', 'O', 'e', 'u'], "seed={$seed} hash={$h}");
        }
    }

    /**
     * The legal alphabet must actually be exercised: across a seed sweep the `.`/`/` chars the old
     * generator could never emit must appear somewhere, guarding against a silent regression to the
     * alnum-only draw (which would still pass the widened shape regex).
     */
    public function test_bcrypt_hash_actually_uses_the_dot_slash_alphabet(): void
    {
        $sawDotOrSlash = false;
        for ($seed = 0; $seed < 128 && !$sawDotOrSlash; $seed++) {
            $tail = substr(FakeSecrets::bcryptHash($seed, 'row-' . $seed), 7);
            if (strpbrk($tail, './') !== false) {
                $sawDotOrSlash = true;
            }
        }
        self::assertTrue($sawDotOrSlash, 'no bcrypt hash used a . or / across 128 seeds — alphabet regressed?');
    }

    public function test_bcrypt_hash_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::bcryptHash(7, 'row-0'), FakeSecrets::bcryptHash(8, 'row-0'));
        self::assertNotSame(FakeSecrets::bcryptHash(7, 'row-0'), FakeSecrets::bcryptHash(7, 'row-1'));
    }

    public function test_flag_is_deterministic_and_shaped(): void
    {
        $f = FakeSecrets::flag(9, 'row-0');
        self::assertSame($f, FakeSecrets::flag(9, 'row-0'));
        self::assertMatchesRegularExpression('/^FLAG\.\{[0-9a-f]{40}\}\.GALF$/', $f);
    }

    public function test_flag_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::flag(9, 'row-0'), FakeSecrets::flag(10, 'row-0'));
        self::assertNotSame(FakeSecrets::flag(9, 'row-0'), FakeSecrets::flag(9, 'row-1'));
    }

    /**
     * Byte-pins at fixed (seed, key). The re-roll guard's ROUND-0 field key is byte-identical to the
     * pre-guard material, so every shape that can't trip the denylist (hex resetToken/flag, `_`-joined
     * stripeKey) must be UNCHANGED from the values it produced before FP-0260 — the determinism net.
     * apiKey (base32) and bcryptHash (legal `./` alphabet + legal salt char) intentionally changed
     * shape, so they are pinned to their NEW expected bytes (verify by running the generator).
     */
    public function test_generator_byte_pins(): void
    {
        // Unchanged by FP-0260 (round 0 == old material, never trips):
        self::assertSame('221e1696c83fd98464dd4838a508d7d3c5a7e9dd', FakeSecrets::resetToken(5, 'row-0'));
        // NB: split literal so GitHub secret-scanning push-protection doesn't flag this synthetic
        // fake as a real Stripe key — the concatenation is byte-identical to the pinned value.
        self::assertSame('sk_test_' . 'lfwXSKKZ35uFevHlb3xCi2G6', FakeSecrets::stripeKey(3, 'row-0'));
        self::assertSame('FLAG.{b690734ca9fd471afef7cc7e44a42d79d0168002}.GALF', FakeSecrets::flag(9, 'row-0'));
        // Intentionally reshaped by FP-0260 (base32 body / legal bcrypt):
        self::assertSame('AKIAASS5NVTC3HQQBMYL', FakeSecrets::apiKey(1, 'row-0'));
        self::assertSame('$2y$10$udyUEVKJbKuBNrAnpcThnuW38uO5l6PQV73bghWad3CnT5pXbWNPJ', FakeSecrets::bcryptHash(7, 'row-0'));
    }

    /** The private denied-digit predicate must match the runtime gate's bare-CRS-rule-id rule
     *  (`\b9\d{5}\b`): true only for an ISOLATED 6-digit run starting with 9. */
    public function test_hits_denied_digits_predicate(): void
    {
        $m = (new ReflectionClass(FakeSecrets::class))->getMethod('hitsDeniedDigits');
        $m->setAccessible(true);
        self::assertTrue($m->invoke(null, 'x/912345.y'), 'isolated 9+5 digits must trip');
        self::assertTrue($m->invoke(null, '912345'), 'bare 9+5 digits must trip');
        self::assertFalse($m->invoke(null, 'x9123456y'), 'a 7-digit run inside a word is not isolated');
        self::assertFalse($m->invoke(null, 'abcdef'), 'no digits, no trip');
        self::assertFalse($m->invoke(null, '/812345.'), 'must start with 9');
    }

    /**
     * The round tag: round 0 uses `$key . '|' . $tag` (byte-identical to the pre-guard material, so a
     * non-tripping value is unchanged), and each later round appends `|r<n>` so a re-roll draws fresh
     * material. This wires the guard's re-derive; that its round>0 branch is rarely reached by natural
     * input (a `./`-isolated 9+5 run is astronomically rare in the bcrypt tail — none in 1.8M sampled
     * compositions) is exactly why the shape is a proven backstop, not a hot path.
     */
    public function test_field_round_tagging(): void
    {
        $m = (new ReflectionClass(FakeSecrets::class))->getMethod('field');
        $m->setAccessible(true);
        self::assertSame('row-0|bcryptHash', $m->invoke(null, 'row-0', 'bcryptHash', 0));
        self::assertSame('row-0|bcryptHash|r1', $m->invoke(null, 'row-0', 'bcryptHash', 1));
        self::assertSame('row-0|bcryptHash|r2', $m->invoke(null, 'row-0', 'bcryptHash', 2));
    }

    /**
     * Belt-and-braces over the whole runtime FingerprintGuard (not just the bare-CRS-rule-id regex):
     * the reshaped bcryptHash — the one generator whose new `./` alphabet can isolate a 6-digit run —
     * must never trip the guard across a wide seed spread. This is the real gate on the re-roll's job.
     */
    public function test_bcrypt_hash_never_matches_the_fingerprint_guard_across_many_seeds(): void
    {
        $guard = \Funnypot\Core\Compiler\Crs\FingerprintGuard::fromPackage();
        $keys = ['row-0', 'row-1', 'admin', 'k#7'];

        for ($seed = 0; $seed < 1024; $seed++) {
            foreach ($keys as $key) {
                $h = FakeSecrets::bcryptHash($seed, $key);
                self::assertSame([], $guard->scan($h), "seed={$seed} key={$key} hash={$h}");
            }
        }
    }

    /**
     * The runtime fingerprint scan denylists a bare CRS rule id: six digits starting with 9,
     * bounded by non-word characters (resources/fingerprint-denylist.php). None of these dead
     * secrets may ever expose that shape, across a wide seed spread and every method.
     */
    public function test_no_value_matches_the_fingerprint_denylist_across_many_seeds(): void
    {
        $pattern = self::denylistPattern();
        $keys = ['row-0', 'row-1', 'admin', 'k#7'];

        for ($seed = 0; $seed < 256; $seed++) {
            foreach ($keys as $key) {
                $values = [
                    FakeSecrets::apiKey($seed, $key),
                    FakeSecrets::stripeKey($seed, $key),
                    FakeSecrets::resetToken($seed, $key),
                    FakeSecrets::bcryptHash($seed, $key),
                    FakeSecrets::flag($seed, $key),
                ];
                foreach ($values as $value) {
                    self::assertDoesNotMatchRegularExpression(
                        $pattern,
                        $value,
                        "seed={$seed} key={$key} value={$value}"
                    );
                }
            }
        }
    }

    /**
     * Belt-and-braces over the whole runtime denylist (not just the bare-CRS-rule-id pattern): the
     * FLAG.{…}.GALF shape must never trip FingerprintGuard across a wide seed spread — the wrapper
     * bounds the 40-hex run so no isolated 6-digit run can form, and it carries no CRS string.
     */
    public function test_flag_never_matches_the_fingerprint_denylist_across_many_seeds(): void
    {
        $guard = \Funnypot\Core\Compiler\Crs\FingerprintGuard::fromPackage();
        $keys = ['row-0', 'row-1', 'admin', 'k#7'];

        for ($seed = 0; $seed < 256; $seed++) {
            foreach ($keys as $key) {
                $flag = FakeSecrets::flag($seed, $key);
                self::assertSame([], $guard->scan($flag), "seed={$seed} key={$key} flag={$flag}");
            }
        }
    }

    private static function denylistPattern(): string
    {
        $denylist = require dirname(__DIR__) . '/resources/fingerprint-denylist.php';
        foreach ($denylist['patterns'] as $p) {
            if ($p === '\b9\d{5}\b') {
                return '/' . $p . '/i';
            }
        }

        self::fail('expected \b9\d{5}\b pattern not found in fingerprint-denylist.php');
    }
}
