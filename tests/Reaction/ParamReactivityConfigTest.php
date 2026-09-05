<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\Reaction\ParamReactionDecorator;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use PHPUnit\Framework\TestCase;

/**
 * Config wiring for the opt-in param reaction: it defaults off, is the trailing positional argument
 * (so every existing positional caller is unchanged), and it does NOT widen the reflect gate — the
 * 'param-reaction' class is AND-composed with isolatedOrigin + evidence exactly like every other
 * reflect class.
 */
final class ParamReactivityConfigTest extends TestCase
{
    private static function vouch(): Closure
    {
        return static function (RequestContext $r, string $class): bool { return true; };
    }

    public function test_defaults_off(): void
    {
        self::assertFalse((new Config())->paramReactivity);
    }

    public function test_is_the_trailing_positional_argument(): void
    {
        // The 29-arg list from ReflectingDecoyGateTest, with paramReactivity appended last.
        $config = new Config(
            'respond', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0,
            true, null, null, null, '', [], true, null, null, null, null, null, [],
            true,   // isolatedOrigin
            false, null, false,
            [],     // reflectClasses
            self::vouch(),
            true    // paramReactivity
        );
        self::assertTrue($config->paramReactivity);
        // The preceding trailing params still landed where they belong.
        self::assertTrue($config->isolatedOrigin);
        self::assertNotNull($config->reflectorAuthorizer);
    }

    public function test_reflect_gate_is_and_not_or_for_param_reaction(): void
    {
        $request = new RequestContext('GET', '/x', 'q=1');
        $class = ParamReactionDecorator::REFLECT_CLASS;

        // Embedded, even with the class explicitly enabled AND an authorizer: withheld (isolatedOrigin
        // dominates). If the gate were an OR this would be true.
        $embedded = new Config();
        $embedded->isolatedOrigin = false;
        $embedded->reflectClasses = [$class => true];
        $embedded->reflectorAuthorizer = self::vouch();
        $embedded->paramReactivity = true;
        self::assertFalse($embedded->serveReflector($class, $request));

        // Isolated + authorized: served.
        $open = new Config();
        $open->isolatedOrigin = true;
        $open->reflectorAuthorizer = self::vouch();
        $open->paramReactivity = true;
        self::assertTrue($open->serveReflector($class, $request));

        // Isolated + authorized but the class subtracted: withheld.
        $subtracted = new Config();
        $subtracted->isolatedOrigin = true;
        $subtracted->reflectorAuthorizer = self::vouch();
        $subtracted->paramReactivity = true;
        $subtracted->reflectClasses = [$class => false];
        self::assertFalse($subtracted->serveReflector($class, $request));

        // Isolated but no evidence (null authorizer): withheld — intent alone never reflects.
        $noEvidence = new Config();
        $noEvidence->isolatedOrigin = true;
        $noEvidence->paramReactivity = true;
        self::assertFalse($noEvidence->serveReflector($class, $request));

        // A null request (position-blind port) carries no evidence: withheld.
        self::assertFalse($open->serveReflector($class, null));
    }
}
