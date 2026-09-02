<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\HoneypotMiddleware;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * FP-0252 Fix B: the serve-delay is carried as SynthesizedResponse::$delayMicros metadata and
 * applied by the emitter/adapter — the core respond() path no longer sleeps inside the host worker.
 */
final class ServeDelayMetadataTest extends TestCase
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

    private function config(int $latencyMs = 0, int $jitterMs = 0): Config
    {
        return new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'seed-x'; },
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            $latencyMs,
            $jitterMs
        );
    }

    private function respond(Config $c): ?object
    {
        return (new Honeypot($this->store(), $c))->respond(new RequestContext('GET', '/multi'));
    }

    public function test_respond_returns_delay_as_metadata_without_sleeping(): void
    {
        $start = microtime(true);
        $r = $this->respond($this->config(750)); // 750 ms — an in-core sleep would be obvious
        $elapsed = microtime(true) - $start;

        self::assertNotNull($r);
        // Core did NOT sleep: the call returns near-instantly (generous CI-safe margin).
        self::assertLessThan(0.5, $elapsed, 'respond() must not sleep in-core');
        // ...but the delay is carried for the emitter to apply.
        self::assertGreaterThanOrEqual(750000, $r->delayMicros);
    }

    public function test_delay_metadata_includes_jitter_within_bounds(): void
    {
        // serveDelayMicros() = (latencyMs + jitter[0..jitterMs]) * 1000.
        $r = $this->respond($this->config(10, 5));

        self::assertNotNull($r);
        self::assertGreaterThanOrEqual(10000, $r->delayMicros);
        self::assertLessThanOrEqual(15000, $r->delayMicros);
    }

    public function test_zero_latency_yields_zero_delay_metadata(): void
    {
        $r = $this->respond($this->config());

        self::assertNotNull($r);
        self::assertSame(0, $r->delayMicros);
    }

    public function test_synthesize_port_never_carries_a_delay(): void
    {
        // The position-blind port never had gates/delay; even with latencyMs configured its result
        // carries delayMicros === 0.
        $engine = new Honeypot($this->store(), $this->config(750));
        $r = $engine->synthesizeFromHandle(FakeHandle::route('GET /multi'), SiteProfile::empty(), 'seed-x|');

        self::assertNotNull($r);
        self::assertSame(0, $r->delayMicros);
    }

    public function test_middleware_applies_the_delay(): void
    {
        // Only the emitter sleep is unit-tested elsewhere; the PSR-15 adapter must also honor the
        // tarpit so PSR hosts don't silently lose it. Use a small delay so the test stays fast.
        $engine = new Honeypot($this->store(), $this->config(30)); // 30 ms
        $factory = new Psr17Factory();
        $middleware = new HoneypotMiddleware($engine, $factory, $factory);

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new Psr17Factory())->createResponse(404);
            }
        };

        $request = (new ServerRequest('GET', '/multi'))->withHeader('Host', 'example.test');

        $start = microtime(true);
        $response = $middleware->process($request, $handler);
        $elapsed = microtime(true) - $start;

        self::assertSame(200, $response->getStatusCode());
        self::assertGreaterThanOrEqual(0.03, $elapsed, 'the middleware must apply the tarpit delay');
    }
}
