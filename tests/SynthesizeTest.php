<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\FakeHandle;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\SiteProfile;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Phase 2: synthesize(Verdict, SiteProfile, seed) is the retained deception content, split out
 * of respond(). Pure function of its inputs + the store; null is the sole "no fake" signal
 * (degrade to the caller's 404 — the engine only ever upgrades a 404, never a 5xx).
 */
final class SynthesizeTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    public function test_synthesize_builds_the_route_fake_a_verdict_points_at(): void
    {
        $engine = new Honeypot($this->store());
        $r = new RequestContext('GET', '/.git/config');
        $verdict = $engine->classify($r, SiteProfile::empty());

        $fake = $engine->synthesize($verdict, SiteProfile::empty(), 'seed-1');

        self::assertNotNull($fake);
        self::assertSame(200, $fake->status);
        self::assertStringContainsString('[core]', $fake->body);
        self::assertSame(['git-config'], $fake->satisfies->templateIds());
    }

    public function test_synthesize_is_deterministic_for_fixed_inputs(): void
    {
        $engine = new Honeypot($this->store());
        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        $a = $engine->synthesize($verdict, SiteProfile::empty(), 'same-seed');
        $b = $engine->synthesize($verdict, SiteProfile::empty(), 'same-seed');

        self::assertNotNull($a);
        self::assertNotNull($b);
        // Body is a pure function of (handle, profile, seed); only the random X-Request-Id varies.
        self::assertSame($a->body, $b->body);
        self::assertSame($a->status, $b->status);
    }

    public function test_clean_verdict_synthesizes_nothing(): void
    {
        $engine = new Honeypot($this->store());
        $verdict = $engine->classify(new RequestContext('GET', '/totally/legit/page'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($engine->synthesize($verdict, SiteProfile::empty(), 'seed'));
    }

    public function test_real_route_collision_declines_synthesis(): void
    {
        // A route handle whose path is a declared real endpoint must not shadow the live route.
        $engine = new Honeypot($this->store());
        $verdict = $engine->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());
        self::assertNotNull($verdict->fakeHandle);

        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return $method === 'GET' && $path === '/.git/config';
        });

        self::assertNull($engine->synthesize($verdict, $profile, 'seed'));
    }

    public function test_synthesize_renders_an_attack_verdict_with_reflected_captures(): void
    {
        $engine = new Honeypot($this->store(), new Config(
            'detect',                            // mode
            null,                                // gate
            'matched-only',                      // pathScope
            null,                                // personaSeed
            'coherent',                          // personaBreadth
            \Funnypot\Response\Style::MINIMAL,   // responseStyle
            'high',                              // severityCeiling
            65536,                               // maxBodyBytes
            0,                                   // latencyMs
            0,                                   // latencyJitterMs
            true                                 // attackEmulation
        ));
        $payload = '<script>alert(document.domain)</script>';
        $verdict = $engine->classify(new RequestContext('GET', '/search', 'q=' . $payload), SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);

        $fake = $engine->synthesize($verdict, SiteProfile::empty(), 'atk-seed');
        self::assertNotNull($fake);
        // The captured payload is reflected — proving captures ride the handle into synthesize().
        self::assertStringContainsString($payload, $fake->body);
    }

    public function test_attack_synthesis_honours_the_severity_ceiling(): void
    {
        // command-injection is critical; the default 'high' ceiling refuses to fabricate it.
        $high = new Honeypot($this->store(), new Config(
            'detect',                            // mode
            null,                                // gate
            'matched-only',                      // pathScope
            null,                                // personaSeed
            'coherent',                          // personaBreadth
            \Funnypot\Response\Style::MINIMAL,   // responseStyle
            'high',                              // severityCeiling
            65536,                               // maxBodyBytes
            0,                                   // latencyMs
            0,                                   // latencyJitterMs
            true                                 // attackEmulation
        ));
        $v = $high->classify(new RequestContext('GET', '/ping', 'host=127.0.0.1;id'), SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $v->classification);
        self::assertNull($high->synthesize($v, SiteProfile::empty(), 'x'));

        $critical = new Honeypot($this->store(), new Config(
            'detect',                            // mode
            null,                                // gate
            'matched-only',                      // pathScope
            null,                                // personaSeed
            'coherent',                          // personaBreadth
            \Funnypot\Response\Style::MINIMAL,   // responseStyle
            'critical',                          // severityCeiling
            65536,                               // maxBodyBytes
            0,                                   // latencyMs
            0,                                   // latencyJitterMs
            true                                 // attackEmulation
        ));
        $v2 = $critical->classify(new RequestContext('GET', '/ping', 'host=127.0.0.1;id'), SiteProfile::empty());
        $fake = $critical->synthesize($v2, SiteProfile::empty(), 'x');
        self::assertNotNull($fake);
        self::assertStringContainsString('uid=0(root)', $fake->body);
    }

    public function test_llm_handle_is_host_injected_core_builds_nothing(): void
    {
        // A FakeHandle{kind:llm} names an app-side synthesizer the host injects; core declines.
        $engine = new Honeypot($this->store());
        $verdict = new Verdict(
            Verdict::SCANNER_PROBE,
            \Funnypot\Detection::none(),
            '',
            0,
            \Funnypot\BotSignalSet::empty(),
            new FakeHandle(FakeHandle::KIND_LLM)
        );

        self::assertNull($engine->synthesize($verdict, SiteProfile::empty(), 'seed'));
    }

    public function test_respond_equals_classify_plus_synthesize_for_a_probe(): void
    {
        // The facade is exactly classify()+synthesize() with the gates layered on: an open-gate
        // respond() and a direct synthesize() produce the same body.
        $store = $this->store();
        $facade = new Honeypot($store, new Config(
            'respond',                                                        // mode
            static function (RequestContext $r): bool { return true; },       // gate
            'matched-only',                                                   // pathScope
            static function (RequestContext $r): string { return 'fixed'; }   // personaSeed
        ));
        $pure = new Honeypot($store);

        $r = new RequestContext('GET', '/.git/config');
        $viaRespond = $facade->respond($r);
        $verdict = $pure->classify($r, SiteProfile::empty());
        $viaSynthesize = $pure->synthesize($verdict, SiteProfile::empty(), 'fixed|');

        self::assertNotNull($viaRespond);
        self::assertNotNull($viaSynthesize);
        self::assertSame($viaRespond->body, $viaSynthesize->body);
    }
}
