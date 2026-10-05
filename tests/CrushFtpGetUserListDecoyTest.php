<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0459: CrushFTP CVE-2025-31161 improper-auth user-enumeration decoy (CISA KEV). The auth-bypass
 * getUserList request (forged CrushAuth cookie + AWS4 Credential header) returns the CrushFTP XML user
 * list with the `<user_list_subitem>crushadmin</user_list_subitem>` scanner witness. Authentic gate: a
 * bare getUserList without the forged-auth header must NOT leak (404 like the real server). Inert.
 */
final class CrushFtpGetUserListDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private const AUTH = ['Authorization' => 'AWS4-HMAC-SHA256 Credential=crushadmin/', 'Cookie' => 'CrushAuth=1111111111_1111111111111111111111111111111'];

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $method, string $query, array $headers = []): string
    {
        $r = $this->engine()->respond(new RequestContext($method, '/WebInterface/function/', $query, $headers, null, 'x.test'));

        return $r !== null ? (string) $r->body : '';
    }

    public function test_auth_bypass_returns_the_user_list(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/WebInterface/function/', 'command=getUserList&serverGroup=MainUsers&c2f=1111', self::AUTH, null, 'x.test'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('text/xml', (string) ($r->headers['Content-Type'] ?? ''));
        self::assertStringContainsString('<user_list_subitem>crushadmin</user_list_subitem>', (string) $r->body,
            'Nettacker crushftp_cve_2025_31161 confirmation witness');
    }

    public function test_post_method_also_works(): void
    {
        $b = $this->body('POST', 'command=getUserList', self::AUTH);
        self::assertStringContainsString('crushadmin', $b, 'the bypass is GET or POST');
    }

    public function test_getuserlist_without_forged_auth_header_does_not_leak(): void
    {
        // Authentic gate: a bare command=getUserList without the AWS4 Credential header 404s on the real
        // server, so the decoy must not serve the user list either.
        self::assertStringNotContainsString('crushadmin', $this->body('GET', 'command=getUserList'));
    }

    public function test_bare_function_path_without_command_does_not_leak(): void
    {
        self::assertStringNotContainsString('crushadmin', $this->body('GET', '', self::AUTH));
    }

    public function test_no_request_byte_reflected(): void
    {
        $b = $this->body('GET', 'command=getUserList&serverGroup=Zcrushsentinel66Z',
            ['Authorization' => 'AWS4-HMAC-SHA256 Credential=Zcrushsentinel66Z/', 'Cookie' => 'CrushAuth=1111111111_1111111111111111111111111111111']);
        self::assertStringContainsString('crushadmin', $b);
        self::assertStringNotContainsString('Zcrushsentinel66Z', $b);
    }
}
