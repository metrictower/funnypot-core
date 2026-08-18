<?php

declare(strict_types=1);

namespace Funnypot\Http;

use Funnypot\RequestContext;
use Psr\Http\Message\ServerRequestInterface;

/**
 * PSR-7 ServerRequest -> RequestContext. Primitives only, matching the core's
 * contract (RequestContext never parses/reflects the body).
 */
final class PsrRequestMapper
{
    public static function map(ServerRequestInterface $request): RequestContext
    {
        $uri = $request->getUri();

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        $host = $uri->getHost() !== '' ? $uri->getHost() : ($headers['Host'] ?? '');
        $scheme = $uri->getScheme() !== '' ? $uri->getScheme() : 'https';

        return new RequestContext(
            $request->getMethod(),
            $uri->getPath(),
            $uri->getQuery(),
            $headers,
            self::readBody($request),
            $host,
            $scheme
        );
    }

    /**
     * Peek at the body without disturbing it for the downstream handler: only
     * read a stream that can be rewound, and always leave it back at position 0
     * so a miss still lets $handler->handle($request) read the body itself.
     */
    private static function readBody(ServerRequestInterface $request): ?string
    {
        $stream = $request->getBody();
        if (!$stream->isReadable() || !$stream->isSeekable()) {
            return null;
        }

        $stream->rewind();
        $body = $stream->getContents();
        $stream->rewind();

        return $body;
    }
}
