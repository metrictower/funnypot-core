<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\Http\BasicCredentials;
use PHPUnit\Framework\TestCase;

/**
 * FP-0007 — the strict HTTP Basic credential parser for the `basic` decoy-session mode. Proves it accepts
 * only a well-formed, plausible `Basic` credential and returns null (throw-free, reflect-free) on every
 * malformed/oversize case, so a garbage Authorization header can never reach a renderer.
 */
final class BasicCredentialsTest extends TestCase
{
    private static function b64(string $raw): string
    {
        return base64_encode($raw);
    }

    public function test_parses_a_plausible_credential(): void
    {
        $c = BasicCredentials::parse('Basic ' . self::b64('admin:s3cret'));
        self::assertSame(['username' => 'admin', 'password' => 's3cret'], $c);
    }

    public function test_scheme_name_is_case_insensitive(): void
    {
        self::assertNotNull(BasicCredentials::parse('basic ' . self::b64('u:p')));
        self::assertNotNull(BasicCredentials::parse('BASIC ' . self::b64('u:p')));
    }

    public function test_accepts_username_alphabet_including_email(): void
    {
        $c = BasicCredentials::parse('Basic ' . self::b64('user.name@example.test:pw'));
        self::assertSame('user.name@example.test', $c['username'] ?? null);
    }

    /** @dataProvider malformed */
    public function test_returns_null_on_malformed_input(string $header): void
    {
        self::assertNull(BasicCredentials::parse($header));
    }

    /** @return array<string,array{0:string}> */
    public function malformed(): array
    {
        return [
            'empty'                 => [''],
            'wrong scheme'          => ['Bearer ' . self::b64('u:p')],
            'no space'              => ['Basic' . self::b64('u:p')],
            'two spaces/second arm' => ['Basic ' . self::b64('u:p') . ' extra'],
            'comma fold'            => ['Basic ' . self::b64('u:p') . ',Basic x'],
            'invalid base64 alpha'  => ['Basic !!!!'],
            'no colon'              => ['Basic ' . self::b64('nocolonhere')],
            'empty username'        => ['Basic ' . self::b64(':pw')],
            'empty password'        => ['Basic ' . self::b64('user:')],
            'username too long'     => ['Basic ' . self::b64(str_repeat('a', 65) . ':pw')],
            'password too long'     => ['Basic ' . self::b64('u:' . str_repeat('p', 129))],
            'bad username char'     => ['Basic ' . self::b64('user name:pw')],
            'colon in password'     => ['Basic ' . self::b64('u:a:b')],
            'control in password'   => ['Basic ' . self::b64("u:p\x01w")],
            'nul in password'       => ['Basic ' . self::b64("u:p\x00w")],
            'oversize token'        => ['Basic ' . str_repeat('A', 600)],
        ];
    }

    public function test_authorization_reads_header_case_insensitively(): void
    {
        $r = new RequestContext('GET', '/manager/html', '', ['authorization' => 'Basic ' . self::b64('u:p')]);
        self::assertSame('Basic ' . self::b64('u:p'), BasicCredentials::authorization($r));
    }

    public function test_authorization_is_empty_when_absent_or_null_request(): void
    {
        self::assertSame('', BasicCredentials::authorization(null));
        self::assertSame('', BasicCredentials::authorization(new RequestContext('GET', '/manager/html')));
    }
}
