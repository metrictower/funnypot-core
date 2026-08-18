<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * Resolves a matcher's `part` to the response region we can synthesize into.
 *
 * From nuclei's http `getMatchPart`/`responseToDSLMap`: empty/`body` → body, `header` →
 * the `all_headers` block, `all` → body concatenated with the header block. A word placed
 * in the body therefore also satisfies an `all` matcher (substring of the concatenation),
 * so `all` routes to the body region.
 *
 * A typed-header part (`content_type`, `server`, `location`, `set_cookie`, …) matches the
 * VALUE of that one response header — nuclei stores it as `data[lower(key with - → _)]`.
 * {@see typedHeader()} maps such a part back to its Go-canonical header name so the
 * synthesizer can emit the required substring into the right header. Numbered variants
 * (`content_type_1`, `body_2`) are second-request corpora we do not produce → unsupported.
 */
final class PartRouter
{
    public const BODY = 'body';
    public const HEADER = 'header';
    public const UNSUPPORTED = '';

    /**
     * Named response headers whose per-header value region we can satisfy by emitting the
     * header. Value is the Go-canonical header name. Deliberately excludes `content_length`
     * (numeric / response-framing) and extractor-defined fields (`version`).
     */
    private const TYPED_HEADERS = [
        'content_type' => 'Content-Type',
        'server' => 'Server',
        'location' => 'Location',
        'set_cookie' => 'Set-Cookie',
        'www_authenticate' => 'WWW-Authenticate',
        'x_powered_by' => 'X-Powered-By',
        'x_cache' => 'X-Cache',
        'accept_ranges' => 'Accept-Ranges',
        'content_disposition' => 'Content-Disposition',
    ];

    public static function region(string $part): string
    {
        $p = strtolower(trim($part));
        if ($p === '' || $p === 'body' || $p === 'all') {
            return self::BODY;
        }
        if ($p === 'header') {
            return self::HEADER;
        }

        return self::UNSUPPORTED;
    }

    /**
     * The Go-canonical header name a typed-header part matches against, or null when the
     * part is not one of the supported single-request response headers.
     */
    public static function typedHeader(string $part): ?string
    {
        $p = strtolower(trim($part));

        return self::TYPED_HEADERS[$p] ?? null;
    }
}
