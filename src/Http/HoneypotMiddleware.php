<?php

declare(strict_types=1);

namespace Funnypot\Core\Http;

use Funnypot\Core\Engine;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 adapter. detect() always runs first and its result is attached to the
 * request as an attribute — PSR-15 has no observer hook of its own, so the
 * attribute is how downstream middleware (the app's own logging/scoring layer)
 * reads it regardless of mode. respond() then decides whether to serve a
 * synthesized response in place of the downstream handler; core untouched.
 */
final class HoneypotMiddleware implements MiddlewareInterface
{
    public const ATTRIBUTE_DETECTION = 'funnypot.detection';

    /** @var Engine */
    private $inverter;

    /** @var ResponseFactoryInterface */
    private $responseFactory;

    /** @var StreamFactoryInterface */
    private $streamFactory;

    public function __construct(
        Engine $inverter,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->inverter = $inverter;
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $context = PsrRequestMapper::map($request);

        $detection = $this->inverter->detect($context);
        $request = $request->withAttribute(self::ATTRIBUTE_DETECTION, $detection);

        $synthesized = $this->inverter->respond($context);
        if ($synthesized === null) {
            return $handler->handle($request);
        }

        return PsrResponseMapper::map($synthesized, $this->responseFactory, $this->streamFactory);
    }
}
