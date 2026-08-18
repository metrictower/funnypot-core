<?php

declare(strict_types=1);

namespace Funnypot\Http;

use Funnypot\SynthesizedResponse;

/**
 * The one opt-in side effect: write a SynthesizedResponse to PHP's output using
 * http_response_code()/header()/echo. Kept out of the pure core so callers that
 * want their own transport (PSR-7, streamed) never pull this in.
 */
final class ResponseEmitter
{
    public static function emit(SynthesizedResponse $response): void
    {
        http_response_code($response->status);

        foreach ($response->headers as $name => $value) {
            // C8 defence-in-depth: skip any header that could split the response.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1
                || preg_match('/[\r\n\x00]/', (string) $value) === 1) {
                continue;
            }
            // Set-Cookie must append (a response can carry several, e.g. a session cookie
            // plus a planted honeytoken); every other header replaces.
            header($name . ': ' . $value, strcasecmp((string) $name, 'Set-Cookie') !== 0);
        }

        echo $response->body;
    }
}
