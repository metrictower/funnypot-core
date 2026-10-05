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
 * FP-0434 (T1+T2): NoSQL operator-injection detection + differential record-dump decoy.
 *
 * T1 (attack-nosql-operator): a NoSQL operator (bracket/form/JSON) on an API/extensionless store-miss
 * path reclassifies to a coherent {"data":[],"total":0} JSON (out of the CRS MySQL-error archetype); a
 * static-document path (.php/.html) keeps the status-quo CRS behavior (the invariant-#5 path guard).
 * T2 (attack-nosql-differential): on the /products and /users collection keys, an operator probe with a
 * plausible value dumps a populated document list (TRUE), an unlikely sentinel (empty/16+hex/tilde) returns
 * empty (FALSE) -> quick_ratio << 0.9; a benign request (no operator) falls through to the store collection.
 * Both 200, never 500; nothing reflected; T3 (auth-bypass -> signed session) is deferred to FP-0561.
 * Fixture: full compiled corpus + attack artifact via Honeypot::respond() with attackEmulation on.
 */
final class NoSqlOperatorInjectionDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    /** @var array<string,Honeypot> per-seed engine cache — caps Honeypot churn across the seed sweeps. */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $method, string $path, string $query = '', ?string $body = null, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext($method, $path, $query, [], $body, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    private function quickRatio(string $a, string $b): float
    {
        $ca = count_chars($a, 1);
        $cb = count_chars($b, 1);
        $m = 0;
        foreach ($ca as $k => $v) {
            if (isset($cb[$k])) {
                $m += min($v, $cb[$k]);
            }
        }
        $t = strlen($a) + strlen($b);

        return $t > 0 ? 2 * $m / $t : 1.0;
    }

    public function test_t1_reclassifies_operator_on_unowned_api_paths(): void
    {
        // query, form-body, and JSON-body operator forms, on store-miss extensionless paths.
        $query = $this->resp('GET', '/zzqshop91/items', 'q[$ne]=');
        $form = $this->resp('POST', '/zzqshop92/items', '', 'username[$ne]=&password[$ne]=');
        $json = $this->resp('POST', '/zzqshop93/api', '', '{"username":{"$ne":null},"password":{"$ne":null}}');
        foreach (['query' => $query, 'form' => $form, 'json' => $json] as $k => $r) {
            self::assertSame(200, $r->status ?? null, "{$k} probe must serve 200");
            self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''), "{$k} CT");
            self::assertStringContainsString('"total":0', $this->body($r), "{$k} must be the coherent JSON empty result");
            self::assertStringNotContainsString('SQL syntax', $this->body($r), "{$k} must NOT be the MySQL error");
        }
    }

    public function test_t1_static_document_path_keeps_crs(): void
    {
        // The invariant-#5 path guard: a .php path must NOT be reclassified to the JSON empty result.
        $r = $this->resp('GET', '/zzx91.php', 'u[$ne]=');
        self::assertNotSame('{"data":[],"total":0}', trim($this->body($r)), '.php path must fall through to CRS, not T1 JSON');
    }

    public function test_t2_differential_populated_vs_empty(): void
    {
        foreach (['/products', '/users'] as $p) {
            $populated = $this->body($this->resp('GET', $p, 'q[$ne]=admin'));
            $empty = $this->body($this->resp('GET', $p, 'q[$ne]=' . str_repeat('a1b2', 8)));
            self::assertStringContainsString('"_id"', $populated, "{$p} plausible probe must dump records");
            self::assertStringContainsString('"total": 6', $populated, "{$p} populated total");
            self::assertStringContainsString('"total":0', $empty, "{$p} unlikely probe must be empty");
            self::assertLessThan(0.85, $this->quickRatio($populated, $empty), "{$p} quick_ratio must be < 0.85");
            self::assertLessThan(0.5 * strlen($populated), strlen($empty), "{$p} empty must be materially shorter");
        }
    }

    public function test_t2_unlikely_sentinels_all_empty(): void
    {
        foreach (['q[$ne]=', 'q[$ne]=' . str_repeat('f', 32), 'q[$ne]=' . str_repeat('~', 8)] as $q) {
            self::assertStringContainsString('"total":0', $this->body($this->resp('GET', '/products', $q)), "{$q} must be empty");
        }
    }

    public function test_t2_benign_falls_through_to_store_collection(): void
    {
        $r = $this->resp('GET', '/products');
        self::assertSame(200, $r->status ?? null);
        self::assertStringNotContainsString('"_id"', $this->body($r), 'benign /products must be the store collection, not the dump decoy');
    }

    public function test_never_500_sweep(): void
    {
        $ops = ['[$ne]', '[$gt]', '[$regex]', '[$where]', '[$in]'];
        $vals = ['admin', '', 'x', str_repeat('f', 32), str_repeat('~', 8), '.*'];
        foreach (['/products', '/users', '/zzunowned9/x'] as $p) {
            foreach ($ops as $op) {
                foreach ($vals as $v) {
                    $r = $this->resp('GET', $p, 'q' . $op . '=' . $v);
                    self::assertNotNull($r, "{$p} q{$op}={$v} must serve");
                    self::assertLessThan(500, $r->status, "{$p} q{$op}={$v} must never 5xx");
                }
            }
        }
    }

    public function test_no_collision_with_fp0387_and_fp0454(): void
    {
        self::assertStringContainsString('is_superuser', $this->body($this->resp('GET', '/api/v1/users', 'password__startswith=pbkdf2')), 'FP-0387 unaffected');
        self::assertSame(401, $this->resp('DELETE', '/api/v1/users/5')->status ?? null, 'FP-0454 unaffected');
    }

    public function test_no_reflection(): void
    {
        $b = $this->body($this->resp('GET', '/products', 'q[$ne]=ZZCANARYZZ'));
        self::assertStringNotContainsString('ZZCANARYZZ', $b, 'the operator value must not be reflected');
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 400; $s++) {
            $pop = $this->body($this->resp('GET', '/products', 'q[$ne]=admin', null, (string) $s));
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $pop), "seed {$s} populated denylist run");
        }
    }
}
