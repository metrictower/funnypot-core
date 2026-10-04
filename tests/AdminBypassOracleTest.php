<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0402: the 403-bypass oracle (attack-admin-403-bypass). Protected admin paths return a realistic
 * nginx 403 by default; a classic proxy/ACL-bypass header (X-Original-URL, X-Forwarded-For: 127.0.0.1,
 * …) or a path-encoding trick (/%2e/<p>, /<p>/., /<p>;) "unlocks" a 200 admin login — safe bait, never
 * a real header-driven oracle (every body/header is a fixed literal; the bypass value is never echoed).
 */
final class AdminBypassOracleTest extends TestCase
{
    /** @var array<string,mixed> */
    private static function index(): array
    {
        return require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    }

    private function engine(): Honeypot
    {
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::index()), $cfg);
    }

    /** @param array<string,string> $headers */
    private function resp(string $path, array $headers = []): ?object
    {
        $h = $this->engine();
        $r = new RequestContext('GET', $path, '', $headers, null, 'x.test');
        $v = $h->classify($r, SiteProfile::empty());

        return $h->synthesizeFromHandle($v->fakeHandle, SiteProfile::empty(), 's', $r);
    }

    private function body(?object $resp): string
    {
        return $resp !== null ? (string) $resp->body : '';
    }

    public function test_bare_protected_path_returns_403(): void
    {
        $resp = $this->resp('/internal');
        self::assertSame(403, $resp->status ?? null);
        self::assertStringContainsString('403 Forbidden', $this->body($resp));
        self::assertStringNotContainsString('Internal Admin', $this->body($resp));
    }

    public function test_every_protected_path_baselines_403(): void
    {
        foreach (['/internal', '/admin-console', '/adminpanel', '/restricted', '/control'] as $p) {
            self::assertSame(403, $this->resp($p)->status ?? null, "$p must baseline 403");
        }
    }

    public function test_rewrite_header_unlocks_200_login(): void
    {
        foreach (['X-Original-URL', 'X-Rewrite-URL', 'X-Forwarded-Host', 'X-Host', 'X-Http-Host-Override'] as $hdr) {
            $resp = $this->resp('/internal', [$hdr => '/admin']);
            self::assertSame(200, $resp->status ?? null, "$hdr must unlock");
            self::assertStringContainsString('Internal Admin', $this->body($resp), "$hdr must serve the login");
        }
    }

    public function test_localhost_ip_spoof_header_unlocks(): void
    {
        foreach (['X-Forwarded-For', 'X-Real-IP', 'True-Client-IP', 'X-Custom-IP-Authorization'] as $hdr) {
            $resp = $this->resp('/restricted', [$hdr => '127.0.0.1']);
            self::assertSame(200, $resp->status ?? null, "$hdr: 127.0.0.1 must unlock");
        }
    }

    public function test_non_localhost_spoof_header_stays_403(): void
    {
        $resp = $this->resp('/internal', ['X-Forwarded-For' => '8.8.8.8']);
        self::assertSame(403, $resp->status ?? null, 'a non-loopback XFF must NOT unlock');
    }

    public function test_path_encoding_tricks_unlock(): void
    {
        foreach (['/%2e/internal', '/control;', '/adminpanel/.'] as $p) {
            $resp = $this->resp($p);
            self::assertSame(200, $resp->status ?? null, "$p trick must unlock");
        }
    }

    public function test_bypass_value_is_never_reflected(): void
    {
        // The unlocked login is a fixed literal — the attacker's header value must never appear in it.
        $marker = 'Zreflbypass7788Z';
        $resp = $this->resp('/internal', ['X-Original-URL' => '/' . $marker]);
        self::assertSame(200, $resp->status ?? null);
        self::assertStringNotContainsString($marker, $this->body($resp), 'no header value may be echoed');
    }

    public function test_trailing_slash_does_not_itself_unlock(): void
    {
        // A trailing slash is a clean-path variant, not a bypass trick: still 403, no login.
        $resp = $this->resp('/internal/');
        self::assertSame(403, $resp->status ?? null);
        self::assertStringNotContainsString('Internal Admin', $this->body($resp));
    }
}
