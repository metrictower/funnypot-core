<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0252 Fix C: a host-supplied policy closure that throws must never escape core as a host 500.
 * Each seam fails to the safe side (a throw can only ever REDUCE what core serves, never widen it),
 * and — where a request has already been recognized as a probe — the decline surfaces on the
 * Observer via the wrapped onOutcome. Harness mirrors GatingTest's synthetic multi-bundle index.
 */
final class HostCallbackSafetyTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
                't-b' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'B'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['AAA'], 'nf' => [], 'h' => [], 'pid' => 'pa', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                    ['s' => 200, 'bw' => ['BBB'], 'nf' => [], 'h' => [], 'pid' => 'pb', 'sev' => 'low', 'sig' => 0, 't' => ['t-b']],
                ]],
                'GET /root' => ['b' => [
                    ['s' => 200, 'bw' => ['ROOT'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'low', 'sig' => 1, 't' => ['t-a']],
                ]],
            ],
        ]);
    }

    private function config(array $overrides = []): Config
    {
        return new Config(
            'respond',
            $overrides['gate'] ?? static function (RequestContext $r): bool { return true; },
            'matched-only',
            $overrides['personaSeed'] ?? null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            false,
            $overrides['trustedBypass'] ?? null,
            $overrides['killSwitch'] ?? null,
            $overrides['probeSignature'] ?? null,
            '',
            []
        );
    }

    private function spy(): Observer
    {
        return new class implements Observer {
            /** @var string[] */
            public $outcomes = [];

            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
                $this->outcomes[] = $reason;
            }
        };
    }

    private function respond(Config $c, string $path, ?Observer $o = null): ?SynthesizedResponse
    {
        return (new Honeypot($this->store(), $c, $o))->respond(new RequestContext('GET', $path));
    }

    public function test_a_throwing_gate_fails_closed(): void
    {
        $spy = $this->spy();
        $c = $this->config(['gate' => static function (RequestContext $r): bool {
            throw new \RuntimeException('boom');
        }]);

        $result = $this->respond($c, '/multi', $spy);

        self::assertNull($result);
        self::assertContains(Outcome::GATE_CLOSED, $spy->outcomes);
    }

    public function test_a_throwing_kill_switch_disables_respond(): void
    {
        $c = $this->config(['killSwitch' => static function (): bool {
            throw new \RuntimeException('boom');
        }]);

        self::assertNull($this->respond($c, '/multi'));
    }

    public function test_a_throwing_trusted_bypass_declines(): void
    {
        $c = $this->config(['trustedBypass' => static function (RequestContext $r): bool {
            throw new \RuntimeException('boom');
        }]);

        self::assertNull($this->respond($c, '/multi'));
    }

    public function test_a_throwing_probe_signature_stays_closed(): void
    {
        $spy = $this->spy();
        // A sig=1 root entry fires only when probeSignature says so; a throwing predicate must
        // decline with NO_SIGNATURE, not serve and not 500.
        $c = $this->config(['probeSignature' => static function (RequestContext $r): bool {
            throw new \RuntimeException('boom');
        }]);

        $result = $this->respond($c, '/root', $spy);

        self::assertNull($result);
        self::assertContains(Outcome::NO_SIGNATURE, $spy->outcomes);
    }

    public function test_a_throwing_persona_seed_falls_back_to_host_seed(): void
    {
        // A throwing personaSeed must degrade to the built-in $r->host seed — deterministic and
        // identical to not configuring the closure — so served bytes match a personaSeed:null run.
        $thrown = $this->respond($this->config(['personaSeed' => static function (RequestContext $r): string {
            throw new \RuntimeException('boom');
        }]), '/multi');
        $control = $this->respond($this->config(['personaSeed' => null]), '/multi');

        self::assertNotNull($thrown);
        self::assertNotNull($control);
        self::assertSame($control->body, $thrown->body);
    }
}
