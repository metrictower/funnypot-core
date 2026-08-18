<?php

declare(strict_types=1);

namespace Funnypot\Http;

use Funnypot\Engine;
use Funnypot\RequestContext;
use Funnypot\SynthesizedResponse;

/**
 * Framework-agnostic convenience for the "call me from your 404 handler" path:
 * an app with no PSR-15 pipeline (or a Laravel exception Handler, see
 * docs/INTEGRATION.md) calls this from wherever it already decides a request is
 * a 404, and falls back to its own 404 page on null.
 */
final class Responder
{
    public static function forRequest(Engine $inv, RequestContext $r): ?SynthesizedResponse
    {
        return $inv->respond($r);
    }
}
