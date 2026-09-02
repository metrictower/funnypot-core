<?php

declare(strict_types=1);

namespace Funnypot\Core\Http;

use Funnypot\Core\SynthesizedResponse;

/**
 * The one opt-in side effect: write a SynthesizedResponse to PHP's output using
 * http_response_code()/header()/echo. Kept out of the pure core so callers that
 * want their own transport (PSR-7, streamed) never pull this in.
 */
final class ResponseEmitter
{
    public static function emit(SynthesizedResponse $response): void
    {
        // FP-0252: the tarpit delay now lives at the transport edge (it was an in-core usleep that
        // blocked the host worker pool). The plain-PHP host path keeps today's wall-clock behavior.
        if ($response->delayMicros > 0) {
            usleep($response->delayMicros);
        }

        http_response_code($response->status);

        foreach ($response->headers as $name => $value) {
            // C8 defence-in-depth: a poisoned NAME could split the response — skip the whole header.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1) {
                continue;
            }
            // A value may be a single string or a list (multi Set-Cookie); apply the CRLF/NUL guard
            // PER ELEMENT so one poisoned element is dropped without losing the rest.
            $values = is_array($value) ? $value : [$value];
            // Set-Cookie must append (a response can carry several, e.g. a session cookie plus a
            // planted honeytoken); every other header replaces. For a multi-value header only the
            // first EMITTED line carries the replace flag; the rest append so all lines survive —
            // and if the first element was dropped as poisoned, the next surviving one inherits it.
            $replace = strcasecmp((string) $name, 'Set-Cookie') !== 0;
            $first = true;
            foreach ($values as $v) {
                if (preg_match('/[\r\n\x00]/', (string) $v) === 1) {
                    continue;
                }
                header($name . ': ' . $v, $first ? $replace : false);
                $first = false;
            }
        }

        echo $response->body;
    }
}
