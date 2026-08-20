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
 * Phase 1: classify() is the single detection path — today's detect() widened to run the
 * attack matcher and to consult the SiteProfile real-route oracle. For every routed case its
 * .detection must equal today's detect(); the new classification/handle/oracle behavior is
 * additive.
 */
final class ClassifyTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function engine(bool $attack = false): Honeypot
    {
        return new Honeypot($this->store(), new Config(
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
            $attack                              // attackEmulation
        ));
    }

    public function test_classify_detection_matches_detect_for_a_routed_probe(): void
    {
        $engine = $this->engine();
        $r = new RequestContext('GET', '/.git/config');

        $verdict = $engine->classify($r, SiteProfile::empty());

        self::assertEquals($engine->detect($r), $verdict->detection);
        self::assertSame(['git-config'], $verdict->detection->templateIds());
    }

    public function test_routed_probe_classifies_scanner_probe_with_route_handle(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());

        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertSame('medium', $verdict->severity);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ROUTE, $verdict->fakeHandle->kind);
        self::assertSame('GET /.git/config', $verdict->fakeHandle->key);
    }

    public function test_clean_miss_classifies_clean_with_no_handle(): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', '/totally/legit/page'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());
        self::assertNull($verdict->fakeHandle);
    }

    public function test_attack_payload_on_unrouted_path_classifies_attack_class(): void
    {
        $r = new RequestContext('GET', '/nope', 'file=../../../../etc/passwd');

        $verdict = $this->engine(true)->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame('attack-lfi-unix', $verdict->fakeHandle->ruleId);
        self::assertSame(['attack-lfi-unix'], $verdict->detection->templateIds());
    }

    public function test_attack_matcher_is_off_when_attack_emulation_disabled(): void
    {
        // detect()-parity: with attack emulation off, an injection on an unrouted path is clean.
        $r = new RequestContext('GET', '/nope', 'file=../../../../etc/passwd');

        $verdict = $this->engine(false)->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    public function test_real_route_oracle_demotes_a_would_be_probe_to_clean(): void
    {
        $profile = new SiteProfile(['git'], static function (string $method, string $path): bool {
            return $path === '/.git/config';
        });

        $verdict = $this->engine()->classify(new RequestContext('GET', '/.git/config'), $profile);

        // A live route on the host is never shadowed — no probe, no handle.
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
        self::assertTrue($verdict->detection->isEmpty());
    }

    public function test_sig1_root_entry_classifies_clean_but_keeps_a_handle(): void
    {
        // A root/homepage-class entry (all bundles sig=1) is an ordinary-visitor path: classify
        // clean natively (no probe signature is a policy input), yet keep the route handle so the
        // facade/policy can still synthesize when it does supply one.
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => ['t-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A']],
            'routes' => [
                'GET /root' => ['b' => [
                    ['s' => 200, 'bw' => ['ROOT'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'low', 'sig' => 1, 't' => ['t-a']],
                ]],
            ],
        ]);
        $engine = new Honeypot($store);

        $verdict = $engine->classify(new RequestContext('GET', '/root'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame('GET /root', $verdict->fakeHandle->key);
        // detect() still signals the underlying match (unchanged).
        self::assertSame(['t-a'], $verdict->detection->templateIds());
    }

    public function test_detect_delegates_to_classify(): void
    {
        $engine = $this->engine();

        foreach (['/.git/config', '/totally/legit/page', '/webpack.config.js'] as $path) {
            $r = new RequestContext('GET', $path);
            self::assertEquals(
                $engine->classify($r, SiteProfile::empty())->detection,
                $engine->detect($r),
                "detect() must equal classify().detection for {$path}"
            );
        }
    }
}
