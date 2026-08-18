<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Respond-mode safety gates, against a synthetic index (the Phase-1 fixture has only
 * singleton bundles, so persona selection needs a hand-built multi-bundle route).
 */
final class GatingTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-crit' => ['sev' => 'critical', 'tags' => ['rce'], 'name' => 'Crit'],
                't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
                't-b' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'B'],
            ],
            'routes' => [
                'GET /crit' => ['b' => [
                    ['s' => 200, 'bw' => ['CRIT'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'critical', 'sig' => 0, 't' => ['t-crit']],
                ]],
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['AAA'], 'nf' => [], 'h' => [], 'pid' => 'pa', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                    ['s' => 200, 'bw' => ['BBB'], 'nf' => [], 'h' => [], 'pid' => 'pb', 'sev' => 'low', 'sig' => 0, 't' => ['t-b']],
                ]],
                // A critical bundle first, then a servable low one — proves the ceiling
                // filters candidates before the seed pick (never leaves a hole).
                'GET /mixed' => ['b' => [
                    ['s' => 200, 'bw' => ['CRITMIX'], 'nf' => [], 'h' => [], 'pid' => 'pc', 'sev' => 'critical', 'sig' => 0, 't' => ['t-crit']],
                    ['s' => 200, 'bw' => ['LOWMIX'], 'nf' => [], 'h' => [], 'pid' => 'pl', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                ]],
                'GET /root' => ['b' => [
                    ['s' => 200, 'bw' => ['ROOT'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'low', 'sig' => 1, 't' => ['t-a']],
                ]],
            ],
        ]);
    }

    private function respond(Config $c, string $path, string $query = ''): ?object
    {
        return (new Honeypot($this->store(), $c))
            ->respond(new RequestContext('GET', $path, $query));
    }

    private function openConfig(array $overrides = []): Config
    {
        return new Config(
            mode: $overrides['mode'] ?? 'respond',
            gate: $overrides['gate'] ?? static fn (RequestContext $r): bool => true,
            personaSeed: $overrides['personaSeed'] ?? static fn (RequestContext $r): string => 'seed-x',
            severityCeiling: $overrides['severityCeiling'] ?? 'high',
            maxBodyBytes: $overrides['maxBodyBytes'] ?? 65536,
            trustedBypass: $overrides['trustedBypass'] ?? null,
            killSwitch: $overrides['killSwitch'] ?? null,
            probeSignature: $overrides['probeSignature'] ?? null,
            exclude: $overrides['exclude'] ?? []
        );
    }

    public function test_kill_switch_suppresses_everything(): void
    {
        $c = $this->openConfig(['killSwitch' => static fn (): bool => true]);
        self::assertNull($this->respond($c, '/multi'));
    }

    public function test_severity_ceiling_refuses_critical_by_default(): void
    {
        self::assertNull($this->respond($this->openConfig(), '/crit'));
    }

    public function test_severity_ceiling_allows_critical_when_raised(): void
    {
        $r = $this->respond($this->openConfig(['severityCeiling' => 'critical']), '/crit');
        self::assertNotNull($r);
        self::assertStringContainsString('CRIT', $r->body);
    }

    public function test_persona_selection_is_deterministic_per_seed(): void
    {
        $a = $this->respond($this->openConfig(['personaSeed' => static fn (RequestContext $r): string => 'same']), '/multi');
        $b = $this->respond($this->openConfig(['personaSeed' => static fn (RequestContext $r): string => 'same']), '/multi');

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body);
    }

    public function test_persona_population_reaches_both_bundles(): void
    {
        $bodies = [];
        foreach (['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's7'] as $seed) {
            $r = $this->respond($this->openConfig(['personaSeed' => static fn (RequestContext $req): string => $seed]), '/multi');
            self::assertNotNull($r);
            $bodies[$r->body] = true;
        }

        // Across the scanner population, both personas are served (never mixed).
        self::assertArrayHasKey('AAA', $bodies);
        self::assertArrayHasKey('BBB', $bodies);
    }

    public function test_max_body_bytes_refuses_oversized(): void
    {
        self::assertNull($this->respond($this->openConfig(['maxBodyBytes' => 0]), '/multi'));
    }

    public function test_root_sig_needs_a_probe_signature(): void
    {
        // sig=1 (root class) with no probeSignature closure serves nothing...
        self::assertNull($this->respond($this->openConfig(), '/root'));
        // ...but fires when the app's probeSignature predicate says so.
        $r = $this->respond(
            $this->openConfig(['probeSignature' => static fn (RequestContext $req): bool => true]),
            '/root'
        );
        self::assertNotNull($r);
        self::assertStringContainsString('ROOT', $r->body);
    }

    public function test_severity_ceiling_filters_candidates_before_pick(): void
    {
        // /mixed has a critical bundle and a low one. Under the default 'high' ceiling
        // the critical is removed BEFORE selection, so EVERY seed serves the low bundle
        // — never a null hole from the seed landing on the refused critical.
        foreach (['s0', 's1', 's2', 's3', 's4', 's5'] as $seed) {
            $r = $this->respond($this->openConfig(['personaSeed' => static fn (RequestContext $req): string => $seed]), '/mixed');
            self::assertNotNull($r, "seed {$seed} left a coverage hole");
            self::assertSame(200, $r->status);
            self::assertStringContainsString('LOWMIX', $r->body);
            self::assertStringNotContainsString('CRITMIX', $r->body);
        }
    }

    public function test_exclude_by_template_id_drops_the_bundle(): void
    {
        self::assertNull($this->respond($this->openConfig(['exclude' => ['t-crit']]), '/crit'));
    }

    public function test_exclude_by_tag_drops_the_bundle(): void
    {
        self::assertNull($this->respond($this->openConfig(['exclude' => ['rce']]), '/crit'));
    }

    public function test_observer_receives_outcomes(): void
    {
        $observer = new class implements \Funnypot\Observer {
            /** @var string[] */
            public array $detections = [];
            /** @var string[] */
            public array $outcomes = [];

            public function onDetection(RequestContext $r, \Funnypot\Detection $d): void
            {
                $this->detections[] = $r->path;
            }

            public function shouldRespond(RequestContext $r, \Funnypot\Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?\Funnypot\SynthesizedResponse $resp, string $reason): void
            {
                $this->outcomes[] = $reason;
            }
        };

        // Served path.
        $inv = new Honeypot($this->store(), $this->openConfig(), $observer);
        $inv->respond(new RequestContext('GET', '/multi'));
        // Gate-closed path.
        $inv2 = new Honeypot($this->store(), new Config(mode: 'respond'), $observer);
        $inv2->respond(new RequestContext('GET', '/multi'));

        self::assertSame(['/multi', '/multi'], $observer->detections);
        self::assertSame([\Funnypot\Outcome::SERVED, \Funnypot\Outcome::GATE_CLOSED], $observer->outcomes);
    }
}
