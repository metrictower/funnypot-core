<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Response\EmulatorRegistry;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0239 — the opt-in gate. Prompt-injection seeding must be OFF by default and, when off, the
 * served body must be byte-identical to pre-FP-0239 output (no seeded block, no behaviour change).
 * This is the "no regression" half of the falsifiable sign-off (spec invariant 7).
 */
final class PromptInjectionGateTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    private function set(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    /** @return array<string,mixed> a real compiled bundle for a taunt-carrying README decoy. */
    private function readmeBundle(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index['routes']['GET /readme.html']['b'][0];
    }

    public function test_disabled_by_default(): void
    {
        // The config gate defaults off — an operator must opt in explicitly.
        self::assertFalse((new Config())->promptInjectionSeeding);
        self::assertNull((new Config())->beaconUrl);
    }

    public function test_gate_off_render_is_byte_identical(): void
    {
        $bundle = $this->readmeBundle();

        // The pre-FP-0239 construction (no extra args) and an explicitly-off construction must render
        // identically, in both styles and across seeds — the new args add nothing when the gate is off.
        $old = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7));
        $off = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), false, []);

        foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
            foreach ([1, 7, 42, 9999] as $seed) {
                $a = $old->render($bundle, $style, $seed);
                $b = $off->render($bundle, $style, $seed);
                self::assertNotNull($a);
                self::assertNotNull($b);
                self::assertSame($a->body, $b->body, "gate-off body must equal pre-change ({$style}, seed {$seed})");
                // And no injection text leaks when the gate is off.
                self::assertStringNotContainsString('already-decommissioned', $b->body);
                self::assertStringNotContainsString('OUT OF SCOPE', $b->body);
            }
        }
    }

    public function test_registry_default_is_off_and_matches_the_old_factory_call(): void
    {
        // The production factory: the old one-arg call and the explicit gate-off call are identical.
        $bundle = $this->readmeBundle();
        $viaOld = EmulatorRegistry::default(7)->find($bundle);
        $viaNew = EmulatorRegistry::default(7, false, [])->find($bundle);
        self::assertNotNull($viaOld);
        self::assertNotNull($viaNew);

        $a = $viaOld->render($bundle, Style::TAUNT, 7);
        $b = $viaNew->render($bundle, Style::TAUNT, 7);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body);
        self::assertStringNotContainsString('already-decommissioned', $a->body);
    }
}
