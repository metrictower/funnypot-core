<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Closure;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0445: permissive-CORS dynamic reflector + canary payload. A sacrificial store-MISS API path carrying an
 * Origin header gets that Origin reflected into Access-Control-Allow-Origin with Access-Control-Allow-Credentials:
 * true (the critical credentialed-CORS misconfig a cross-origin scanner confirms) plus a JSON body leaking a
 * seeded canary session token + API key. reflects_input routes the serve through the three-term reflector gate,
 * so it serves ONLY from an isolated origin whose authorizer vouches, and is WITHHELD inline in a response-owning
 * host — where echoing Origin into ACAO would be a live vulnerability. Engine memoized per (seed, isolated, auth).
 */
final class CorsReflectorDecoyTest extends TestCase
{
    private const SERVE_PATH = '/api/auth/session';

    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
    private static $engines = [];

    private function engine(bool $isolated, bool $authorizes, string $seed = 'fixed'): Honeypot
    {
        $k = ($isolated ? '1' : '0') . ($authorizes ? '1' : '0') . $seed;
        if (isset(self::$engines[$k])) {
            return self::$engines[$k];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;
        $cfg->isolatedOrigin = $isolated;
        $cfg->reflectorAuthorizer = $authorizes
            ? static function (RequestContext $r, string $class): bool { return true; }
            : null;

        return self::$engines[$k] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function probe(string $path, ?string $origin, bool $isolated, bool $authorizes, string $seed = 'fixed'): ?object
    {
        $headers = $origin === null ? [] : ['Origin' => $origin];

        return $this->engine($isolated, $authorizes, $seed)->respond(new RequestContext('GET', $path, '', $headers, null, 'x.test'));
    }

    public function test_isolated_authorized_reflects_origin_with_credentials_and_canary(): void
    {
        $r = $this->probe(self::SERVE_PATH, 'https://evil.attacker.test', true, true);
        self::assertNotNull($r, 'isolated + authorized must serve the reflector');
        self::assertSame(200, $r->status);
        self::assertSame('https://evil.attacker.test', $r->headers['Access-Control-Allow-Origin'] ?? null, 'Origin reflected into ACAO');
        self::assertSame('true', $r->headers['Access-Control-Allow-Credentials'] ?? null, 'credentials allowed — the critical CORS misconfig');
        self::assertStringContainsString('"authenticated":true', (string) $r->body);
        self::assertStringContainsString('session_token', (string) $r->body, 'leaks a canary session token');
        self::assertStringContainsString('api_key', (string) $r->body, 'leaks a canary API key');
    }

    /** THE SAFETY REGRESSION GUARD: operator intent alone (isolated, no authorizer evidence) serves nothing. */
    public function test_isolated_without_authorizer_is_withheld(): void
    {
        self::assertNull($this->probe(self::SERVE_PATH, 'https://evil.test', true, false), 'isolated but unvouched must withhold');
    }

    /** THE FAIL-SAFE: an embedded host never reflects, even with an authorizer that vouches. */
    public function test_embedded_host_never_reflects_even_when_authorized(): void
    {
        self::assertNull($this->probe(self::SERVE_PATH, 'https://evil.test', false, true), 'embedded host must never reflect Origin into ACAO');
    }

    public function test_no_origin_header_declines(): void
    {
        self::assertNull($this->probe(self::SERVE_PATH, null, true, true), 'no Origin ⇒ no CORS probe ⇒ plain 404 on a MISS path');
    }

    public function test_all_sacrificial_paths_reflect(): void
    {
        $paths = ['/api/auth/session', '/api/session', '/api/v1/user/keys', '/api/user',
            '/api/users/me', '/api/account', '/api/v1/me', '/api/v1/account', '/api/v2/user'];
        foreach ($paths as $p) {
            $r = $this->probe($p, 'https://x.test', true, true);
            self::assertNotNull($r, "{$p} must serve");
            self::assertSame('https://x.test', $r->headers['Access-Control-Allow-Origin'] ?? null, "{$p} reflects Origin");
        }
    }

    /** HIT paths with their own recon surfaces are excluded — no 404 regression when an Origin header rides along. */
    public function test_hit_paths_not_shadowed(): void
    {
        foreach (['/api/me', '/api/profile', '/api/whoami'] as $p) {
            $r = $this->probe($p, 'https://x.test', false, false);
            self::assertNotNull($r, "{$p} must keep its existing surface");
            self::assertSame(200, $r->status, "{$p} must not be 404'd by the reflector");
        }
    }

    /** An encoded CRLF in the Origin must never split a header — the whole response fails closed. */
    public function test_crlf_in_origin_fails_closed(): void
    {
        $r = $this->probe(self::SERVE_PATH, "https://e%0d%0aSet-Cookie:x=1", true, true);
        if ($r !== null) {
            self::assertSame(0, preg_match('/[\r\n]/', (string) ($r->headers['Access-Control-Allow-Origin'] ?? '')), 'no CRLF in ACAO');
            self::assertArrayNotHasKey('Set-Cookie', $r->headers, 'no injected header');
        } else {
            self::assertNull($r, 'declining the CRLF probe is safe');
        }
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 300; $s++) {
            $r = $this->probe(self::SERVE_PATH, 'https://x.test', true, true, (string) $s);
            self::assertNotNull($r, "seed {$s} must serve");
            self::assertSame(0, preg_match('/\b9\d{5}\b/', (string) $r->body), "seed {$s} denylist run");
        }
    }
}
