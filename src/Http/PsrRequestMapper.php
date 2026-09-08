<?php

declare(strict_types=1);

namespace Funnypot\Core\Http;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;
use Psr\Http\Message\ServerRequestInterface;

/**
 * PSR-7 ServerRequest -> RequestContext. Primitives only, matching the core's
 * contract (RequestContext never parses/reflects the body).
 */
final class PsrRequestMapper
{
    /**
     * Hard cap on the request body we buffer into RequestContext::$rawBody — the SAME value the
     * plain-PHP path uses (RequestContext::fromGlobals, php://input read at 65536). An uncapped
     * getContents() on a multi-GB POST would OOM the host worker; this bounds it and makes the two
     * adapters agree byte-for-byte on rawBody for oversized bodies.
     */
    private const MAX_BODY_BYTES = 65536;

    public static function map(ServerRequestInterface $request): RequestContext
    {
        try {
            $target = $request->getRequestTarget();
        } catch (\Throwable $e) {
            return self::rejected();
        }
        if (!BoundedInspection::rawTargetAccepted($target)) {
            return self::rejected();
        }

        try {
            $uri = $request->getUri();
            $path = $uri->getPath();
            $query = $uri->getQuery();
        } catch (\Throwable $e) {
            return self::rejected();
        }
        if (!BoundedInspection::targetComponentsAccepted($path, $query)) {
            return self::rejected();
        }

        try {
            $headers = BoundedInspection::canonicalPsrHeaders($request->getHeaders());
        } catch (\Throwable $e) {
            $headers = [];
        }

        // PSR-7 header access is case-insensitive by contract, so a lowercase h2 `host` and an h1
        // `Host` resolve identically here — the $headers array preserves wire casing, so the old
        // `$headers['Host']` lookup missed the h2 form and flapped the persona across protocol
        // versions. strtolower() the fallback because Uri::getHost() is normalized lowercase but a
        // header line keeps its wire casing, so EXAMPLE.com (h1) and example.com (h2) must not seed
        // differently on a relative-URI request. The URI host still wins when present.
        try {
            $uriHost = BoundedInspection::host($uri->getHost());
            $scheme = $uri->getScheme() !== '' ? $uri->getScheme() : 'https';
        } catch (\Throwable $e) {
            $uriHost = '';
            $scheme = 'https';
        }
        $host = $uriHost !== '' ? $uriHost : strtolower(self::headerValue($headers, 'Host'));

        return new RequestContext(
            $request->getMethod(),
            $path,
            $query,
            $headers,
            self::readBody($request),
            $host,
            $scheme,
            // The h2 self-consistency bot signal (an HTTP/2 request must not carry Connection) was
            // blind for every PSR-15 host because this arg defaulted to ''. PSR-7 returns '1.1' /
            // '2' / '2.0'; Honeypot::isHttp2() normalizes any of them.
            $request->getProtocolVersion()
        );
    }

    private static function rejected(): RequestContext
    {
        return new RequestContext('GET', '/', '', [], null, '', 'https', '', false);
    }

    /** @param array<string,string> $headers */
    private static function headerValue(array $headers, string $wanted): string
    {
        foreach ($headers as $name => $value) {
            if (strcasecmp($name, $wanted) === 0) {
                return BoundedInspection::host($value);
            }
        }

        return '';
    }

    /**
     * Peek at the body without disturbing it for the downstream handler: only
     * read a stream that can be rewound, and always leave it back at position 0
     * so a miss still lets $handler->handle($request) read the body itself.
     *
     * Capped at MAX_BODY_BYTES so a huge body can never OOM the host — the read loop stops at the
     * cap, and PSR-7 read($n) may return short reads so a single read(65536) is not enough. Loop
     * TERMINATION is unconditional (the buffer strictly grows and is hard-capped); the memory ceiling
     * additionally assumes read($n) honours its "up to $n bytes" contract (all mainstream impls do —
     * Nyholm/Guzzle/php-temp), the same assumption fromGlobals makes of file_get_contents(maxlen). The
     * whole read is throw-safe: a stream that lies about isSeekable()/throws on rewind() degrades to
     * "no body captured" (null) rather than escaping as a host 500 (same fail-safe family as Fix C).
     * The rewind is best-effort in a finally so the downstream handler still sees the body at 0.
     */
    private static function readBody(ServerRequestInterface $request): ?string
    {
        $stream = $request->getBody();
        if (!$stream->isReadable() || !$stream->isSeekable()) {
            return null;
        }

        try {
            $stream->rewind();

            $body = '';
            while (strlen($body) < self::MAX_BODY_BYTES && !$stream->eof()) {
                $chunk = $stream->read(self::MAX_BODY_BYTES - strlen($body));
                if ($chunk === '') {
                    // A stream that returns '' without flipping eof() — stop rather than spin.
                    break;
                }
                $body .= $chunk;
            }

            return $body;
        } catch (\Throwable $e) {
            return null;
        } finally {
            try {
                $stream->rewind();
            } catch (\Throwable $e) {
                // Best-effort: a stream that cannot rewind is the downstream handler's problem to
                // detect, but the mapper must not throw on the way out.
            }
        }
    }
}
