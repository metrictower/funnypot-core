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
 * FP-0463: JetBrains TeamCity CVE-2024-27198 auth-bypass decoy (CISA KEV). owns_path override on /hax
 * dispatching on the ?jsp= servlet-path-confusion query: server-info XML (recon), canned admin-create,
 * canned API token. Inert (no real account/token), no request byte reflected. Stateful backdoor-reuse
 * detection is the app follow-up.
 */
final class TeamCityDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $ceiling = 'high'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling, 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $method, string $query, string $ceiling = 'high'): string
    {
        $r = $this->engine($ceiling)->respond(new RequestContext($method, '/hax', $query, [], null, 'x.test'));

        return $r !== null ? (string) $r->body : '';
    }

    public function test_server_recon_returns_teamcity_xml(): void
    {
        $b = $this->body('GET', 'jsp=/app/rest/server;.jsp');
        self::assertStringContainsString('buildNumber', $b);
        self::assertStringContainsString('server version="2023.11.3', $b, 'affected-side version, scanner confirmation');
        self::assertStringContainsString('internalId', $b);
    }

    public function test_users_endpoint_returns_admin_user(): void
    {
        $b = $this->body('POST', 'jsp=/app/rest/users;.jsp');
        self::assertStringContainsString('<user', $b);
        self::assertStringContainsString('SYSTEM_ADMIN', $b);
    }

    public function test_tokens_endpoint_returns_token(): void
    {
        // id-agnostic: a follow-up using the id the decoy returned (id:2) must still hit the token case.
        foreach (['jsp=/app/rest/users/id:1/tokens;.jsp', 'jsp=/app/rest/users/id:2/tokens;.jsp'] as $q) {
            $b = $this->body('POST', $q);
            self::assertStringContainsString('<token', $b, "token case for {$q}");
            self::assertStringNotContainsString('<user', $b, "{$q} must not fall through to the user case");
        }
    }

    public function test_unanchored_jsp_does_not_over_match(): void
    {
        // `(^|&)jsp=` so a param like ?xjsp=1 does NOT trigger the decoy.
        self::assertStringNotContainsString('buildNumber', $this->body('GET', 'xjsp=/app/rest/server;.jsp'));
    }

    public function test_serves_at_default_high_ceiling(): void
    {
        self::assertStringContainsString('buildNumber', $this->body('GET', 'jsp=/app/rest/server;.jsp', 'high'));
    }

    public function test_bare_hax_without_jsp_does_not_trigger(): void
    {
        self::assertStringNotContainsString('buildNumber', $this->body('GET', ''));
    }

    public function test_no_request_byte_reflected(): void
    {
        $r = $this->engine()->respond(new RequestContext('POST', '/hax', 'jsp=/app/rest/users;.jsp', [], '{"username":"Zteamcitysentinel55Z"}', 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('<user', $b);
        self::assertStringNotContainsString('Zteamcitysentinel55Z', $b);
    }
}
