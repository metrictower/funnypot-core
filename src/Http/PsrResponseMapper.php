<?php

declare(strict_types=1);

namespace Funnypot\Core\Http;

use Funnypot\Core\SynthesizedResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * SynthesizedResponse -> PSR-7 response. The factories are injected (no hard
 * dependency on one PSR-17 implementation) so any app's own factory pair works.
 */
final class PsrResponseMapper
{
    public static function map(
        SynthesizedResponse $response,
        ResponseFactoryInterface $responseFactory,
        StreamFactoryInterface $streamFactory
    ): ResponseInterface {
        $psrResponse = $responseFactory->createResponse($response->status);

        foreach ($response->headers as $name => $value) {
            // C8 defence-in-depth: a poisoned NAME could split the response — skip the whole header,
            // mirroring Http\ResponseEmitter's guard for the plain-PHP path.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1) {
                continue;
            }
            // A value may be a single string or a list (multi Set-Cookie). Apply the CRLF/NUL guard
            // PER ELEMENT so one poisoned element is dropped without losing the rest; PSR-7 accepts
            // string|string[] on withHeader() natively and emits multiple lines.
            $values = [];
            foreach (is_array($value) ? $value : [$value] as $v) {
                if (preg_match('/[\r\n\x00]/', (string) $v) === 1) {
                    continue;
                }
                $values[] = (string) $v;
            }
            // When EVERY element is poisoned, skip the header entirely — never call
            // withHeader($name, []), which several PSR-7 implementations reject.
            if ($values === []) {
                continue;
            }
            $psrResponse = $psrResponse->withHeader($name, $values);
        }

        return $psrResponse->withBody($streamFactory->createStream($response->body));
    }
}
