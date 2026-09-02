<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Detection;
use Funnypot\Core\Http\PsrResponseMapper;
use Funnypot\Core\SynthesizedResponse;
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

    public function test_multi_value_set_cookie_maps_to_multiple_psr_headers(): void
    {
        // Fix E: a session cookie AND a planted honeytoken must coexist under one Set-Cookie name.
        $synthesized = new SynthesizedResponse(
            200,
            ['Set-Cookie' => ['fp_role=user; Path=/', 'PHPSESSID=abc; HttpOnly']],
            'body',
            Detection::none()
        );

        $factory = new Psr17Factory();
        $response = PsrResponseMapper::map($synthesized, $factory, $factory);

        self::assertCount(2, $response->getHeader('Set-Cookie'));
        self::assertSame('fp_role=user; Path=/', $response->getHeader('Set-Cookie')[0]);
        self::assertSame('PHPSESSID=abc; HttpOnly', $response->getHeader('Set-Cookie')[1]);
    }

    public function test_single_string_headers_map_byte_identically(): void
    {
        // Fix E regression pin: every current producer emits plain strings — unchanged.
        $synthesized = new SynthesizedResponse(
            200,
            ['Content-Type' => 'text/plain', 'X-Request-Id' => 'deadbeef'],
            '[core]',
            Detection::none()
        );

        $factory = new Psr17Factory();
        $response = PsrResponseMapper::map($synthesized, $factory, $factory);

        self::assertSame('text/plain', $response->getHeaderLine('Content-Type'));
        self::assertSame('deadbeef', $response->getHeaderLine('X-Request-Id'));
        self::assertCount(1, $response->getHeader('Content-Type'));
    }

    public function test_a_fully_poisoned_multi_value_header_is_skipped_entirely(): void
    {
        // Fix E addendum: when every element is CRLF-poisoned, skip the header — never call
        // withHeader($name, []), which several PSR-7 implementations reject.
        $synthesized = new SynthesizedResponse(
            200,
            ['Set-Cookie' => ["a=1\r\nInjected: x", "b=2\r\nInjected: y"]],
            'body',
            Detection::none()
        );

        $factory = new Psr17Factory();
        $response = PsrResponseMapper::map($synthesized, $factory, $factory);

        self::assertFalse($response->hasHeader('Set-Cookie'));
    }
}
