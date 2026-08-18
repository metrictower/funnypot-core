<?php

declare(strict_types=1);

namespace Funnypot\Laravel;

use Funnypot\RequestContext;

/**
 * Illuminate\Http\Request -> RequestContext. Only this bridge (src/Laravel/*)
 * references Illuminate\* — always by FQCN, never imported with `use` — so the
 * package itself carries no hard Laravel dependency; illuminate/support stays a
 * composer "suggest", not a "require" (see composer.json).
 */
final class LaravelRequestMapper
{
    public static function map(\Illuminate\Http\Request $request): RequestContext
    {
        $headers = [];
        foreach ($request->headers->all() as $name => $values) {
            $headers[$name] = implode(', ', (array) $values);
        }

        $content = $request->getContent();

        return new RequestContext(
            $request->getMethod(),
            $request->getPathInfo(),
            (string) $request->getQueryString(),
            $headers,
            is_string($content) ? $content : null,
            (string) $request->getHost(),
            (string) $request->getScheme()
        );
    }
}
