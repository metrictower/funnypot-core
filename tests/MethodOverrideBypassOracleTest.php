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
 * FP-0454: HTTP method-override auth-bypass oracle. /api/v1/{users,keys,tokens}/{id} return 401 for a
 * direct state-changing verb (DELETE/PUT/PATCH) or a bare GET/POST; a POST/GET that smuggles the verb
 * via a method-override header (3 name-folded conditions covering 5 spellings) or a _method-style
 * query/body param flips to 200 success JSON — VulnAPI's status-only bypass confirmation. The success
 * id is fabricated; nothing attacker-supplied is reflected. Pure template-data (attack-method-override-
 * bypass), no engine change. Fixture: the full compiled corpus (nuclei-index.full.php) + the attack
 * artifact, driven via Honeypot::respond() with attackEmulation on.
 */
final class MethodOverrideBypassOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    /** @param array<string,string> $headers */
    private function resp(string $method, string $path, string $query = '', array $headers = [], ?string $body = null, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext($method, $path, $query, $headers, $body, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    private const TARGETS = ['/api/v1/users/5', '/api/v1/keys/abc-123', '/api/v1/tokens/9f'];

    public function test_direct_state_changing_verbs_401(): void
    {
        foreach (self::TARGETS as $p) {
            foreach (['DELETE', 'PUT', 'PATCH'] as $m) {
                $r = $this->resp($m, $p);
                self::assertSame(401, $r->status ?? null, "{$m} {$p} must be 401");
                self::assertStringContainsString('"error":"unauthorized"', $this->body($r), "{$m} {$p} denial body");
                self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''), "{$m} {$p} CT");
            }
        }
    }

    public function test_bare_get_and_post_without_override_401(): void
    {
        foreach (['GET', 'POST'] as $m) {
            $r = $this->resp($m, '/api/v1/users/5');
            self::assertSame(401, $r->status ?? null, "bare {$m} must be 401 (locked API)");
        }
    }

    public function test_override_header_unlocks_200_all_spellings(): void
    {
        // 5 VulnAPI spellings collapse to 3 name-folded conditions.
        $spellings = ['X-HTTP-Method-Override', 'X-Http-Method-Override', 'X-HTTP-Method', 'X-Http-Method', 'X-Method-Override'];
        foreach ($spellings as $h) {
            $r = $this->resp('POST', '/api/v1/users/5', '', [$h => 'DELETE']);
            self::assertSame(200, $r->status ?? null, "{$h}: DELETE must unlock 200");
            self::assertStringContainsString('"status":"success"', $this->body($r), "{$h} success body");
        }
    }

    public function test_override_query_param_unlocks_200(): void
    {
        foreach (['_method', 'method', 'httpMethod', '_httpMethod'] as $p) {
            $r = $this->resp('POST', '/api/v1/users/5', $p . '=DELETE');
            self::assertSame(200, $r->status ?? null, "query {$p}=DELETE must unlock");
        }
        // mid-string param still anchors on the dedicated query surface.
        self::assertSame(200, $this->resp('POST', '/api/v1/users/5', 'foo=1&_method=PUT')->status ?? null);
    }

    public function test_override_body_param_unlocks_200(): void
    {
        $r = $this->resp('POST', '/api/v1/keys/5', '', [], '_method=PATCH&x=1');
        self::assertSame(200, $r->status ?? null, 'body _method=PATCH must unlock');
    }

    public function test_safe_verb_and_benign_param_stay_401(): void
    {
        self::assertSame(401, $this->resp('POST', '/api/v1/users/5', '', ['X-HTTP-Method-Override' => 'GET'])->status ?? null, 'override to GET must not unlock');
        self::assertSame(401, $this->resp('POST', '/api/v1/users/5', 'method=list')->status ?? null, 'benign ?method=list must not unlock');
        self::assertSame(401, $this->resp('POST', '/api/v1/users/5', 'q=DELETE')->status ?? null, 'a DELETE value in an unrelated param must not unlock');
    }

    public function test_no_reflection(): void
    {
        // A marker in the path id and in the override value must never appear in any served body.
        $deny = $this->body($this->resp('DELETE', '/api/v1/users/ZmarkerPathZ'));
        self::assertStringNotContainsString('ZmarkerPathZ', $deny, 'path id must not be reflected in the 401');
        $unlock = $this->body($this->resp('POST', '/api/v1/users/ZmarkerPathZ', '', ['X-HTTP-Method-Override' => 'DELETE']));
        self::assertStringNotContainsString('ZmarkerPathZ', $unlock, 'path id must not be reflected in the 200');
        self::assertSame(1, preg_match('/"id":"[0-9a-f]{12}"/', $unlock), 'the 200 id must be a fabricated 12-hex token');
    }

    public function test_collection_route_unchanged(): void
    {
        $r = $this->resp('GET', '/api/v1/users');
        self::assertSame(200, $r->status ?? null, 'bare collection must still serve the 200 decoy');
        self::assertStringNotContainsString('"error":"unauthorized"', $this->body($r), 'collection must not be the bypass oracle');
    }

    public function test_no_5xx_anywhere(): void
    {
        foreach (self::TARGETS as $p) {
            foreach (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] as $m) {
                foreach ([[], ['X-HTTP-Method-Override' => 'DELETE']] as $h) {
                    $r = $this->resp($m, $p, '', $h);
                    if ($r !== null) {
                        self::assertLessThan(500, $r->status, "{$m} {$p} must never 5xx");
                    }
                }
            }
        }
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 600; $s++) {
            $b = $this->body($this->resp('POST', '/api/v1/users/5', '', ['X-HTTP-Method-Override' => 'DELETE'], null, (string) $s));
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist run");
            self::assertStringNotContainsString('Server:', $b);
        }
    }
}
