<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\RequestContext;
use Funnypot\Response\Style;
use PHPUnit\Framework\TestCase;

/**
 * $decoySessionKey is the per-deploy secret that will sign the decoy mock-auth session
 * cookie. It is additive-only here: stored verbatim, off by default, and appended at the
 * very end of the ctor so every existing positional caller is unaffected.
 */
final class DecoySessionConfigTest extends TestCase
{
    public function test_defaults_to_null(): void
    {
        $c = new Config();

        self::assertNull($c->decoySessionKey);
    }

    public function test_property_assignment_exposes_the_value(): void
    {
        $c = new Config();
        $c->decoySessionKey = 'deploy-secret';

        self::assertSame('deploy-secret', $c->decoySessionKey);
    }

    public function test_ctor_arg_exposes_the_value(): void
    {
        $c = new Config(
            'detect',
            null,
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            false,
            null,
            null,
            null,
            '',
            [],
            true,
            null,
            null,
            null,
            null,
            'deploy-secret'
        );

        self::assertSame('deploy-secret', $c->decoySessionKey);
    }

    /**
     * Existing positional callers (elsewhere in the codebase) pass args only up through
     * $exclude and rely on everything after it defaulting — this must keep compiling and
     * running unchanged now that $decoySessionKey sits at the very end of the signature.
     */
    public function test_preexisting_positional_usage_still_constructs(): void
    {
        $c = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate
            'matched-only',                                             // pathScope
            static function (RequestContext $r): string { return 'seed-x'; }, // personaSeed
            'coherent',                                                 // personaBreadth
            Style::MINIMAL,                                             // responseStyle
            'high',                                                     // severityCeiling
            65536,                                                      // maxBodyBytes
            0,                                                          // latencyMs
            0,                                                          // latencyJitterMs
            false,                                                      // attackEmulation
            null,                                                       // trustedBypass
            null,                                                       // killSwitch
            null,                                                       // probeSignature
            '',                                                         // seedSalt
            []                                                          // exclude
        );

        self::assertSame('respond', $c->mode);
        self::assertNull($c->decoySessionKey);
    }
}
