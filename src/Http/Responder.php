<?php

declare(strict_types=1);

namespace Funnypot\Core\Http;

use Funnypot\Core\Engine;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;

/**
 * Framework-agnostic convenience for the "call me from your 404 handler" path:
 * an app with no PSR-15 pipeline calls this from wherever it already decides a request is
 * a 404, and falls back to its own 404 page on null.
 */
final class Responder
{
    /**
     * FP-0252: the optional tarpit delay is carried on the returned SynthesizedResponse as
     * $delayMicros (the core no longer sleeps). A caller with its own transport is responsible for
     * applying it — sleep for $delayMicros before writing, or (for an async host) schedule a
     * non-blocking timer. Ignoring it is fail-safe: it can only make the host respond FASTER, never
     * block it. The shipped ResponseEmitter / HoneypotMiddleware apply it for you.
     */
    public static function forRequest(Engine $inv, RequestContext $r): ?SynthesizedResponse
    {
        return $inv->respond($r);
    }
}
