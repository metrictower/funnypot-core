<?php

declare(strict_types=1);

namespace Funnypot\Tests\Http;

use Funnypot\Detection;
use Funnypot\Http\PsrResponseMapper;
use Funnypot\SynthesizedResponse;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

final class PsrResponseMapperTest extends TestCase
{
    public function test_maps_status_headers_and_body(): void
    {
        $synthesized = new SynthesizedResponse(
            200,
            ['Content-Type' => 'text/plain'],
            '[core]',
            Detection::none()
        );

        $factory = new Psr17Factory();
        $response = PsrResponseMapper::map($synthesized, $factory, $factory);

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        self::assertSame('[core]', (string) $response->getBody());
    }

    public function test_drops_a_crlf_poisoned_header_defensively(): void
    {
        // C8 defence-in-depth: the compiler already guards against this, but the
        // mapper never trusts it blindly — mirrors Http\ResponseEmitter's guard.
        $synthesized = new SynthesizedResponse(
            200,
            ['X-Bad' => "value\r\nInjected: true"],
            'body',
            Detection::none()
        );

        $factory = new Psr17Factory();
        $response = PsrResponseMapper::map($synthesized, $factory, $factory);

        self::assertFalse($response->hasHeader('X-Bad'));
    }
}
