<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * PersonaIdentity::productVersion() (chrome-move fingerprint fix): a stable-per-deployment version
 * string for a product key, shared by any tier (a skin's banner, a future core-template) that reads
 * the same PersonaIdentity for one deployment — so two tiers never independently roll two different
 * "server version" claims for the same host.
 */
final class PersonaIdentityProductVersionTest extends TestCase
{
    public function test_same_seed_and_product_yields_identical_version(): void
    {
        for ($seed = 0; $seed < 20; $seed++) {
            $a = PersonaIdentity::fromSeed($seed);
            $b = PersonaIdentity::fromSeed($seed);
            self::assertSame($a->productVersion('mysql'), $b->productVersion('mysql'), "seed {$seed} must be deterministic");
        }
    }

    public function test_recognized_product_picks_from_its_pool(): void
    {
        $pool = [
            '10.6.14-MariaDB-log',
            '10.11.6-MariaDB',
            '8.0.35-0ubuntu0.22.04.1',
            '5.7.42-log',
            '10.5.23-MariaDB-1:10.5.23+maria~ubu2004',
        ];
        for ($seed = 0; $seed < 30; $seed++) {
            $version = PersonaIdentity::fromSeed($seed)->productVersion('mysql');
            self::assertContains($version, $pool, "seed {$seed} must pick a plausible MySQL/MariaDB version");
        }
    }

    public function test_unrecognized_product_is_total_not_throwing(): void
    {
        $version = PersonaIdentity::fromSeed(3)->productVersion('some-future-product');
        self::assertNotSame('', $version);
        self::assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/', $version, 'unrecognized product falls back to a generic semver-shaped pool');
    }

    public function test_different_products_can_diverge_for_the_same_seed(): void
    {
        $identity = PersonaIdentity::fromSeed(5);
        // Not a hard guarantee for every seed (small pools), but across many seeds at least one must
        // diverge, proving productVersion() is actually keyed by $product and not just by seed.
        $sawDivergence = false;
        for ($seed = 0; $seed < 40; $seed++) {
            $identity = PersonaIdentity::fromSeed($seed);
            if ($identity->productVersion('mysql') !== $identity->productVersion('some-other-product')) {
                $sawDivergence = true;
                break;
            }
        }
        self::assertTrue($sawDivergence, 'productVersion must vary by product, not collapse every product to one shared pick');
    }

    public function test_versions_diverge_across_seeds(): void
    {
        $versions = [];
        for ($seed = 0; $seed < 30; $seed++) {
            $versions[] = PersonaIdentity::fromSeed($seed)->productVersion('mysql');
        }
        self::assertGreaterThan(1, count(array_unique($versions)), 'the version banner must not collapse to one fixed value across deployments');
    }
}
