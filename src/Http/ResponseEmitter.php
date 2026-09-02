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

        // FP-0252: if the host has already flushed output, skip ALL header emission — calling
        // http_response_code()/header() now would raise PHP warnings and serve a torn response.
        // The body is still echoed: the caller asked for emission and body-only is the least-bad
        // deterministic outcome.
        if (!headers_sent()) {
            http_response_code($response->status);
            foreach (self::headerLines($response) as $line) {
                header($line[0], $line[1]);
            }
        }

        echo $response->body;
    }

    /**
     * @internal Pure projection of a SynthesizedResponse to the exact ordered header lines to emit,
     * so the header logic is unit-testable without a SAPI (emit() consumes it). Each entry is
     * [line, replace] where $line is 'Name: value' and $replace is the second arg to header().
     * Post CRLF/NUL guard, post multi-value expansion, plus a synthesized Content-Length when the
     * response declares neither Content-Length nor Transfer-Encoding.
     *
     * @return array<int,array{0:string,1:bool}>
     */
    public static function headerLines(SynthesizedResponse $response): array
    {
        $lines = [];
        $hasContentLength = false;
        $hasTransferEncoding = false;

        foreach ($response->headers as $name => $value) {
            // C8 defence-in-depth: a poisoned NAME could split the response — skip the whole header.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1) {
                continue;
            }

            // Case-insensitive key scan for the Content-Length synthesis decision below (on the
            // declared keys, per the plan — independent of whether a value survives the guard).
            $lname = strtolower((string) $name);
            if ($lname === 'content-length') {
                $hasContentLength = true;
            } elseif ($lname === 'transfer-encoding') {
                $hasTransferEncoding = true;
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
                $lines[] = [$name . ': ' . $v, $first ? $replace : false];
                $first = false;
            }
        }

        // Every mainstream origin sends Content-Length for a fixed body, so an emitter that never
        // does is the anomaly — this REDUCES fingerprintability. strlen() counts bytes (correct for
        // the wire). Skip it when the response already declares a Content-Length or is chunked, and
        // for the status classes where RFC 9110 §8.6 forbids the header (1xx informational and 204
        // No Content) — sending it there is itself a tell on a bare SAPI (proxies strip it anyway).
        $status = $response->status;
        $forbidsContentLength = $status === 204 || ($status >= 100 && $status <= 199);
        if (!$hasContentLength && !$hasTransferEncoding && !$forbidsContentLength) {
            $lines[] = ['Content-Length: ' . strlen($response->body), true];
        }

        return $lines;
    }
}
