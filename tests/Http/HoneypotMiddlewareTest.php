<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Engine;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Http\HoneypotMiddleware;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class HoneypotMiddlewareTest extends TestCase
{
    public function test_overlong_exact_target_bypasses_engine_and_preserves_downstream_request(): void
    {
        $engine = $this->countingEngine();
        $factory = new Psr17Factory();
        $middleware = new HoneypotMiddleware($engine, $factory, $factory);
        foreach ([4097, 65536] as $targetBytes) {
            $body = \Nyholm\Psr7\Stream::create('abcdef');
            $body->read(2);
            $request = (new ServerRequest('POST', 'https://example.test/short', ['X-Test' => 'value'], $body))
                ->withRequestTarget(str_repeat('x', $targetBytes));
            $handler = $this->capturingHandler();

            $response = $middleware->process($request, $handler);

            self::assertSame(0, $engine->calls);
            self::assertSame(404, $response->getStatusCode());
            self::assertSame($request->getRequestTarget(), $handler->received->getRequestTarget());
            self::assertSame($request->getUri(), $handler->received->getUri());
            self::assertSame($request->getHeaders(), $handler->received->getHeaders());
            self::assertSame($body, $handler->received->getBody());
            self::assertSame(2, $body->tell());
            self::assertTrue($handler->received->getAttribute(HoneypotMiddleware::ATTRIBUTE_DETECTION)->isEmpty());
        }
    }

    public function test_throwing_exact_target_declines_without_engine_or_uri_access(): void
    {
        $engine = $this->countingEngine();
        $factory = new Psr17Factory();
        $request = new class('GET', '/') extends ServerRequest {
            public function getRequestTarget(): string
            {
                throw new \RuntimeException('target unavailable');
            }

            public function getUri(): \Psr\Http\Message\UriInterface
            {
                throw new \RuntimeException('URI must not be read');
            }
        };
        $handler = $this->capturingHandler();

        (new HoneypotMiddleware($engine, $factory, $factory))->process($request, $handler);

        self::assertSame(0, $engine->calls);
        self::assertTrue($handler->received->getAttribute(HoneypotMiddleware::ATTRIBUTE_DETECTION)->isEmpty());
    }

    public function test_short_custom_target_with_oversized_uri_declines_before_engine_and_body(): void
    {
        $engine = $this->countingEngine();
        $factory = new Psr17Factory();
        $uri = new class('/') extends \Nyholm\Psr7\Uri {
            public function getPath(): string
            {
                return str_repeat('p', 4097);
            }
        };
        $body = \Nyholm\Psr7\Stream::create('abcdef');
        $body->read(3);
        $request = (new ServerRequest('POST', $uri, [], $body))->withRequestTarget('/short');
        $handler = $this->capturingHandler();

        (new HoneypotMiddleware($engine, $factory, $factory))->process($request, $handler);

        self::assertSame(0, $engine->calls);
        self::assertSame(3, $body->tell());
        self::assertSame($body, $handler->received->getBody());
    }

    public function test_exact_4096_custom_target_reaches_engine(): void
    {
        $engine = $this->countingEngine();
        $factory = new Psr17Factory();
        $request = (new ServerRequest('GET', '/short'))->withRequestTarget(str_repeat('x', 4096));

        (new HoneypotMiddleware($engine, $factory, $factory))->process($request, $this->capturingHandler());

        self::assertSame(2, $engine->calls, 'accepted middleware runs detect and respond');
    }

    public function test_mapper_rejection_after_stateful_target_accessor_still_bypasses_engine(): void
    {
        $engine = $this->countingEngine();
        $factory = new Psr17Factory();
        $request = new class('GET', '/') extends ServerRequest {
            /** @var int */
            private $targetCalls = 0;

            public function getRequestTarget(): string
            {
                $this->targetCalls++;
                if ($this->targetCalls === 1) {
                    return '/short';
                }
                throw new \RuntimeException('changed target accessor');
            }
        };

        (new HoneypotMiddleware($engine, $factory, $factory))->process($request, $this->capturingHandler());

        self::assertSame(0, $engine->calls);
    }

    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../../resources/compiled/nuclei-index.php');
    }

    /** @return Engine&object{calls:int} */
    private function countingEngine(): Engine
    {
        return new class implements Engine {
            /** @var int */
            public $calls = 0;

            public function detect(RequestContext $r): Detection
            {
                $this->calls++;
                return Detection::none();
            }

            public function respond(RequestContext $r): ?SynthesizedResponse
            {
                $this->calls++;
                return null;
            }

            public function classify(RequestContext $r, SiteProfile $profile): Verdict
            {
                $this->calls++;
                return Verdict::clean();
            }

            public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?SynthesizedResponse
            {
                $this->calls++;
                return null;
            }

            public function synthesizeFromHandle(?FakeHandle $handle, SiteProfile $profile, string $seed): ?SynthesizedResponse
            {
                $this->calls++;
                return null;
            }
        };
    }

    /** @return RequestHandlerInterface&object{received:?ServerRequestInterface} */
    private function capturingHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            /** @var ServerRequestInterface|null */
            public $received;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->received = $request;
                return (new Psr17Factory())->createResponse(404);
            }
        };
    }

    private function middleware(string $mode = 'respond'): HoneypotMiddleware
    {
        $inverter = new Honeypot($this->store(), new Config(
            $mode,                                                       // mode
            static function (RequestContext $r): bool { return true; }   // gate
        ));

        $factory = new Psr17Factory();

        return new HoneypotMiddleware($inverter, $factory, $factory);
    }

    public function test_known_probe_path_returns_synthesized_psr_response(): void
    {
        $request = new ServerRequest('GET', 'https://example.test/.git/config');
        $handler = new class implements RequestHandlerInterface {
            /** @var bool */
            public $called = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;

                return (new Psr17Factory())->createResponse(404);
            }
        };

        $response = $this->middleware()->process($request, $handler);

        self::assertFalse($handler->called, 'downstream handler must not run on a hit');
        self::assertSame(200, $response->getStatusCode());
        $body = (string) $response->getBody();
        self::assertStringContainsString('[core]', $body);
        self::assertStringNotContainsStringIgnoringCase('<html', $body);
        self::assertTrue($response->hasHeader('Content-Type'));
    }

    public function test_miss_calls_the_downstream_handler(): void
    {
        $request = new ServerRequest('GET', 'https://example.test/totally/legit/page');
        $handler = new class implements RequestHandlerInterface {
            /** @var bool */
            public $called = false;
            /** @var ServerRequestInterface|null */
            public $received = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                $this->received = $request;

                return (new Psr17Factory())->createResponse(404);
            }
        };

        $response = $this->middleware()->process($request, $handler);

        self::assertTrue($handler->called);
        self::assertSame(404, $response->getStatusCode());

        // detect() always runs and is exposed to downstream middleware as a
        // request attribute, since PSR-15 has no observer hook of its own.
        $detection = $handler->received->getAttribute(HoneypotMiddleware::ATTRIBUTE_DETECTION);
        self::assertInstanceOf(Detection::class, $detection);
        self::assertTrue($detection->isEmpty());
    }

    public function test_detect_only_mode_never_serves_a_fake_but_still_attaches_detection(): void
    {
        $request = new ServerRequest('GET', 'https://example.test/.git/config');
        $handler = new class implements RequestHandlerInterface {
            /** @var ServerRequestInterface|null */
            public $received = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->received = $request;

                return (new Psr17Factory())->createResponse(404);
            }
        };

        $response = $this->middleware('detect')->process($request, $handler);

        self::assertSame(404, $response->getStatusCode());
        $detection = $handler->received->getAttribute(HoneypotMiddleware::ATTRIBUTE_DETECTION);
        self::assertInstanceOf(Detection::class, $detection);
        self::assertTrue($detection->matched);
        self::assertSame(['git-config'], $detection->templateIds());
    }

    public function test_a_throwing_observer_does_not_500_the_host(): void
    {
        // FP-0252 Fix C: an Observer whose every method throws must not escape core into the host.
        $observer = new class implements Observer {
            public function onDetection(RequestContext $r, Detection $d): void
            {
                throw new \RuntimeException('boom');
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                throw new \RuntimeException('boom');
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
                throw new \RuntimeException('boom');
            }
        };

        $inverter = new Honeypot($this->store(), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; }
        ), $observer);
        $factory = new Psr17Factory();
        $middleware = new HoneypotMiddleware($inverter, $factory, $factory);

        $handler = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return (new Psr17Factory())->createResponse(404);
            }
        };

        // Probe path: shouldRespond throws ⇒ veto ⇒ the middleware falls through to the handler's
        // 404. The point is that NO Throwable escapes as a host 500.
        $probe = $middleware->process(new ServerRequest('GET', 'https://example.test/.git/config'), $handler);
        self::assertSame(404, $probe->getStatusCode());

        // Miss path: the downstream handler's own 404, never a 500.
        $miss = $middleware->process(new ServerRequest('GET', 'https://example.test/totally/legit/page'), $handler);
        self::assertSame(404, $miss->getStatusCode());
    }
}
