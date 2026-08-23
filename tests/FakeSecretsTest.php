<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Support\Fake\FakeSecrets;
use PHPUnit\Framework\TestCase;

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
        self::assertMatchesRegularExpression('/^AKIA[A-Z0-9]{16}$/', $k);
        self::assertNotSame('AKIAIOSFODNN7EXAMPLE', $k);
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
        self::assertMatchesRegularExpression('/^\$2y\$10\$[A-Za-z0-9]{53}$/', $h);
    }

    public function test_bcrypt_hash_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeSecrets::bcryptHash(7, 'row-0'), FakeSecrets::bcryptHash(8, 'row-0'));
        self::assertNotSame(FakeSecrets::bcryptHash(7, 'row-0'), FakeSecrets::bcryptHash(7, 'row-1'));
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
