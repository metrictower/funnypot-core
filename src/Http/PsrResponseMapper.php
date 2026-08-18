<?php

declare(strict_types=1);

namespace Funnypot\Http;

use Funnypot\SynthesizedResponse;
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
            // C8 defence-in-depth: skip anything that could split the response,
            // mirroring Http\ResponseEmitter's guard for the plain-PHP path.
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1
                || preg_match('/[\r\n\x00]/', (string) $value) === 1) {
                continue;
            }
            $psrResponse = $psrResponse->withHeader($name, $value);
        }

        return $psrResponse->withBody($streamFactory->createStream($response->body));
    }
}
