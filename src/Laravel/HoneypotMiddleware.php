<?php

declare(strict_types=1);

namespace Funnypot\Laravel;

use Closure;
use Funnypot\Engine;

/**
 * Laravel-style middleware (handle($request, $next)), mirroring the flow of
 * Http\HoneypotMiddleware with Illuminate's Request/Response instead of PSR-7:
 * detect (attached as a request attribute for the app's own logging) -> respond
 * -> serve the fake or pass through to $next. Core untouched; see
 * LaravelRequestMapper for why Illuminate\* is referenced by FQCN only.
 */
final class HoneypotMiddleware
{
    public const ATTRIBUTE_DETECTION = 'funnypot.detection';

    public function __construct(private Engine $inverter)
    {
    }

    /**
     * @return \Illuminate\Http\Response|mixed
     */
    public function handle(\Illuminate\Http\Request $request, Closure $next)
    {
        $context = LaravelRequestMapper::map($request);

        $detection = $this->inverter->detect($context);
        $request->attributes->set(self::ATTRIBUTE_DETECTION, $detection);

        $synthesized = $this->inverter->respond($context);
        if ($synthesized === null) {
            return $next($request);
        }

        return LaravelResponseMapper::map($synthesized);
    }
}
