<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\RequestContext;
use PHPUnit\Framework\TestCase;

/**
 * deploySeed() is the per-deploy, cross-request-stable seed for one host-wide persona identity.
 * It intentionally takes no RequestContext (one deploy = one identity to everyone), and its
 * NUL-separated prefix keeps it in a space seedFor() never emits — so it can never coincide with
 * a per-attacker persona seed.
 */
final class DeploySeedTest extends TestCase
{
    public function test_stable_regardless_of_request(): void
    {
        $c = new Config();
        $c->seedSalt = 'site-salt';

        // No request is involved, so any two callers on the same deploy see the same seed.
        self::assertSame($c->deploySeed(), $c->deploySeed());
        self::assertIsInt($c->deploySeed());
    }

    public function test_differs_by_seed_salt(): void
    {
        $a = new Config();
        $a->seedSalt = 'A';
        $b = new Config();
        $b->seedSalt = 'B';

        self::assertNotSame($a->deploySeed(), $b->deploySeed());
    }

    public function test_explicit_deploy_seed_is_honored(): void
    {
        $c = new Config();
        $c->seedSalt = 'A';
        $c->deploySeed = 'explicit-material';

        self::assertSame(crc32("deploy\0explicit-material"), $c->deploySeed());

        // An explicit value overrides the salt: same salt, different explicit seed => different result.
        $d = new Config();
        $d->seedSalt = 'A';
        $d->deploySeed = 'other-material';
        self::assertNotSame($c->deploySeed(), $d->deploySeed());

        // Empty string falls back to the salt (treated as unset).
        $e = new Config();
        $e->seedSalt = 'A';
        $e->deploySeed = '';
        self::assertSame(crc32("deploy\0A"), $e->deploySeed());
    }

    public function test_distinct_from_the_per_attacker_persona_seed(): void
    {
        $c = new Config();
        $c->seedSalt = 'shared';
        $r = new RequestContext('GET', '/', '', [], null, 'victim.example');

        // The NUL separator keeps the deploy seed in a space seedFor() never emits, so the two seed
        // spaces stay disjoint.
        self::assertNotSame(crc32($c->seedFor($r)), $c->deploySeed());
    }

    /**
     * seedFor() joins with '|', and Host is attacker-controlled — so a '|' separator here would let
     * a request forging `Host: deploy` reproduce the deploy seed (crc32('deploy|'.$salt) both ways).
     * The NUL separator, which no Host or personaSeed value can carry, closes that collision.
     */
    public function test_host_deploy_cannot_collide_with_deploy_seed(): void
    {
        $c = new Config();
        $c->seedSalt = 'shared';

        // A request whose Host is literally 'deploy'.
        $r = new RequestContext('GET', '/', '', [], null, 'deploy');
        self::assertNotSame(crc32($c->seedFor($r)), $c->deploySeed(), 'Host: deploy must not reproduce the deploy seed');

        // And a personaSeed override that returns 'deploy'.
        $c2 = new Config();
        $c2->seedSalt = 'shared';
        $c2->personaSeed = static function (RequestContext $r): string {
            return 'deploy';
        };
        self::assertNotSame(crc32($c2->seedFor($r)), $c2->deploySeed(), 'personaSeed "deploy" must not reproduce the deploy seed');
    }
}
