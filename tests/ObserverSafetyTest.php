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
 * FP-0252 Fix C: a throwing Observer must never turn a would-be 404 into a host 500. onDetection /
 * onOutcome throws are swallowed (signal loss only); a shouldRespond throw is treated as a veto and
 * surfaces as Outcome::VETOED via the wrapped onOutcome.
 */
final class ObserverSafetyTest extends TestCase
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
            ],
        ]);
    }

    private function config(): Config
    {
        return new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only', null, 'coherent', Style::MINIMAL);
    }

    private function respond(Observer $o, string $path = '/multi'): ?SynthesizedResponse
    {
        return (new Honeypot($this->store(), $this->config(), $o))->respond(new RequestContext('GET', $path));
    }

    public function test_a_throwing_on_detection_does_not_prevent_serving(): void
    {
        $o = new class implements Observer {
            public function onDetection(RequestContext $r, Detection $d): void
            {
                throw new \RuntimeException('boom');
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
            }
        };

        $result = $this->respond($o);

        self::assertNotNull($result, 'a broken onDetection must not stop the serve');
        self::assertSame(200, $result->status);
    }

    public function test_a_throwing_should_respond_becomes_a_veto(): void
    {
        $o = new class implements Observer {
            /** @var string[] */
            public $outcomes = [];

            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                throw new \RuntimeException('boom');
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
                $this->outcomes[] = $reason;
            }
        };

        $result = $this->respond($o);

        self::assertNull($result, 'a throwing shouldRespond fails toward NOT serving');
        self::assertContains(Outcome::VETOED, $o->outcomes);
    }

    public function test_a_throwing_on_outcome_is_swallowed_on_serve_and_decline(): void
    {
        // onOutcome throws on BOTH the SERVED path and the declined() path; neither may escape.
        $o = new class implements Observer {
            public function onDetection(RequestContext $r, Detection $d): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
                throw new \RuntimeException('boom');
            }
        };

        // SERVED path: a probe that serves — the throwing onOutcome must be swallowed.
        $served = $this->respond($o, '/multi');
        self::assertNotNull($served);

        // Declined path: gate closed ⇒ declined() calls onOutcome, which throws — must be swallowed.
        $closed = new Config('respond'); // null gate ⇒ closed
        $declined = (new Honeypot($this->store(), $closed, $o))->respond(new RequestContext('GET', '/multi'));
        self::assertNull($declined);
    }
}
