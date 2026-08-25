<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * Proves the runtime wiring that carries the per-deploy identity seed to the template tier's
 * renderer. Agent A's DirectiveRenderer honours an injected personaSeed (unit-tested separately);
 * this pins that the seed actually THREADS THROUGH the construction path the engine uses —
 * TemplateAttackEmulator::fromPackage/fromFile → ctor → DirectiveRenderer — so {{persona.*}} in a
 * served attack response is a function of the deploy seed, not the per-attacker render seed.
 *
 * The Honeypot ctor computes $config->deploySeed() once and passes it as this exact argument
 * (TemplateAttackEmulator::fromPackage([], $personaSeed)); when the seed did not thread, every
 * deploy rendered the same identity and this test fails.
 *
 * Probe path: GET /xmlrpc.php?rsd renders the Really Simple Discovery document, whose homePageLink
 * carries {{persona.company.domain}} — a pure function of the identity seed.
 */
final class PersonaSeedWiringTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    /** Render the RSD document under a given deploy seed and return its persona domain. */
    private function rsdDomain(?int $personaSeed): string
    {
        $emulator = TemplateAttackEmulator::fromFile(self::COMPILED, [], $personaSeed);
        $r = $emulator->emulate(new RequestContext('GET', '/wp/xmlrpc.php', 'rsd', [], null));
        self::assertNotNull($r, 'RSD probe must render');
        self::assertStringNotContainsString('{{', $r->body, 'no directive may be left unrendered');
        self::assertSame(1, preg_match('~homePageLink>https://([^/]+)/~', $r->body, $m), 'RSD must carry a persona domain');

        return $m[1];
    }

    public function test_deploy_seed_threads_into_rendered_persona(): void
    {
        // Across a spread of deploy seeds the rendered identity must vary — proof the seed reaches
        // the renderer. (Uniqueness over a set is robust to an incidental single-pair collision.)
        $domains = [];
        foreach ([1, 2, 3, 4, 5, 6, 7, 8] as $seed) {
            $domains[] = $this->rsdDomain($seed);
        }
        self::assertGreaterThan(1, count(array_unique($domains)), 'persona domain must depend on the deploy seed');
    }

    public function test_same_deploy_seed_is_deterministic(): void
    {
        // One deploy = one identity to everyone: the same seed renders the same domain every time.
        self::assertSame($this->rsdDomain(4242), $this->rsdDomain(4242));
    }

    public function test_null_seed_is_backcompat_and_still_renders(): void
    {
        // A missing wiring site (null seed) degrades to per-request identity, never crashes — the
        // RSD still renders a well-formed persona domain.
        $domain = $this->rsdDomain(null);
        self::assertNotSame('', $domain);
    }

    public function test_from_package_accepts_the_deploy_seed(): void
    {
        // fromPackage is the exact factory the Honeypot ctor calls with $config->deploySeed();
        // it must forward the seed so the packaged rules render the deploy identity. Uniqueness over
        // a set proves forwarding without depending on any one seed pair differing.
        $domains = [];
        foreach ([11111, 22222, 33333, 44444, 55555] as $seed) {
            $r = TemplateAttackEmulator::fromPackage([], $seed)
                ->emulate(new RequestContext('GET', '/wp/xmlrpc.php', 'rsd', [], null));
            self::assertNotNull($r);
            self::assertSame(1, preg_match('~homePageLink>https://([^/]+)/~', $r->body, $m));
            $domains[] = $m[1];
        }
        self::assertGreaterThan(1, count(array_unique($domains)), 'fromPackage must forward the deploy seed to the renderer');
    }
}
