<?php

declare(strict_types=1);

namespace Funnypot\Tests\Http;

use Funnypot\Config;
use Funnypot\Detection;
use Funnypot\Http\HoneypotMiddleware;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class HoneypotMiddlewareTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../../resources/compiled/nuclei-index.php');
    }

    private function middleware(string $mode = 'respond'): HoneypotMiddleware
    {
        $inverter = new Honeypot($this->store(), new Config(
            mode: $mode,
            gate: static fn (RequestContext $r): bool => true
        ));

        $factory = new Psr17Factory();

        return new HoneypotMiddleware($inverter, $factory, $factory);
    }

    public function test_known_probe_path_returns_synthesized_psr_response(): void
    {
        $request = new ServerRequest('GET', 'https://example.test/.git/config');
        $handler = new class implements RequestHandlerInterface {
            public bool $called = false;

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
            public bool $called = false;
            public ?ServerRequestInterface $received = null;

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
            public ?ServerRequestInterface $received = null;

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
}
