<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Contracts\Evaluator;
use Funnypot\Core\Engine;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Phase 3/4: SiteProfile + the deterministic seed are first-class inputs, and the engine is a
 * pure two-phase Evaluator. The same engine serves every position×action combo as data — it
 * cannot tell which combo it is in, which is the point (design §5).
 */
final class PositionBlindTest extends TestCase
{
    private function engine(): Honeypot
    {
        return new Honeypot(new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php'));
    }

    public function test_honeypot_is_a_two_phase_evaluator_and_engine(): void
    {
        $engine = $this->engine();

        self::assertInstanceOf(Evaluator::class, $engine);
        self::assertInstanceOf(Engine::class, $engine);
    }

    public function test_fallback_position_empty_profile_reproduces_the_probe_path(): void
    {
        // deceive-AFTER (classic honeypot): no real app behind the engine, every path fair game.
        $engine = $this->engine();
        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNotNull($engine->synthesize($verdict, SiteProfile::empty(), 'seed'));
    }

    public function test_before_position_real_route_passes_through_untouched(): void
    {
        // deceive-BEFORE (deceptive WAF): a live route on the host is never classified as a probe
        // and never shadowed by a fake.
        $engine = $this->engine();
        $profile = new SiteProfile(['git'], static function (string $method, string $path): bool {
            return $path === '/.git/config';
        });

        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), $profile);
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);

        // Even handed a route handle, synthesize() declines a collision with the live route.
        $probeVerdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());
        self::assertNull($engine->synthesize($probeVerdict, $profile, 'seed'));
    }

    public function test_block_combo_never_calls_synthesize(): void
    {
        // block-BEFORE / block-AFTER: the policy returns block from its matrix; classify() ran but
        // synthesize() is simply never invoked. Core did detection only — nothing else happened.
        $engine = $this->engine();
        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        // The Verdict is the whole of what a block decision consumes; no fake is built.
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNotNull($verdict->detection);
    }

    public function test_seed_makes_synthesis_a_pure_function(): void
    {
        // The seed is an explicit synthesize() argument; a fixed seed is byte-stable, and a
        // stateless engine gives a multi-step actor a coherent sequence.
        $engine = $this->engine();
        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        $first = $engine->synthesize($verdict, SiteProfile::empty(), 'actor-42');
        $again = $engine->synthesize($verdict, SiteProfile::empty(), 'actor-42');

        self::assertNotNull($first);
        self::assertSame($first->body, $again->body);
    }
}
