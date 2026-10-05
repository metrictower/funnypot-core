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
 * FP-0388: error-based SQLi oracle. Artemis's mixed-quote `'"` error probe (which 50-sqli does not match)
 * returns the believable MySQL 1064 error frame at 200 — in the query/body (attack-sqli-error-probe) AND in
 * any of the 50+ fuzzed HTTP headers (attack-sqli-header-probe, via in:headers). The `-1` baseline carries
 * no quote -> no match -> clean, so Artemis's error-vs-clean differential fires. One dialect (MySQL),
 * never 500. Fixture: full compiled corpus via Honeypot::respond(); engine memoized per seed.
 */
final class SqlErrorOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var array<string,Honeypot> */
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

    /** @param array<string,string> $headers */
    private function probe(string $query = '', array $headers = [], string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', '/s.php', $query, $headers, null, 'x.test'));
    }

    /** A probe that MUST serve a response (the error-oracle cases). */
    private function sqlError(string $query = '', array $headers = [], string $seed = 'fixed'): object
    {
        $r = $this->probe($query, $headers, $seed);
        self::assertNotNull($r, 'the error probe must serve a response');

        return $r;
    }

    private function hasSqlError(?object $r): bool
    {
        // A clean request may legitimately be null (plain 404) — that is "no SQL error".
        return $r !== null && strpos((string) $r->body, 'SQL syntax') !== false;
    }

    public function test_query_error_probe_both_quote_orders(): void
    {
        foreach (['q=%27%22', 'q=%22%27', 'id=1%27%22'] as $q) {
            $r = $this->sqlError($q);
            self::assertTrue($this->hasSqlError($r), "{$q} must return a SQL error");
            self::assertLessThan(500, $r->status, "{$q} must never 5xx");
        }
    }

    public function test_header_error_probe_across_fuzzed_headers(): void
    {
        foreach (['X-Forwarded-For', 'X-Real-IP', 'X-Rewrite-URL', 'User-Agent', 'Cookie', 'Referer'] as $h) {
            $r = $this->sqlError('', [$h => '\'"']);
            self::assertTrue($this->hasSqlError($r), "SQLi in {$h} must return a SQL error");
            self::assertLessThan(500, $r->status, "{$h} must never 5xx");
        }
    }

    public function test_baseline_and_benign_are_clean(): void
    {
        self::assertFalse($this->hasSqlError($this->probe('q=-1')), '-1 baseline must be clean (differential)');
        self::assertFalse($this->hasSqlError($this->probe('', ['User-Agent' => 'Mozilla/5.0 (X11; Linux)'])), 'a benign UA must not trigger the error');
        self::assertFalse($this->hasSqlError($this->probe('q=hello')), 'a benign query must be clean');
    }

    public function test_compound_sqli_still_handled_no_regression(): void
    {
        // The generic 50-sqli must still answer ' or 1=1 / union payloads (this ticket only adds the '" gap).
        self::assertTrue($this->hasSqlError($this->sqlError('q=1%27%20or%20%271%27%3D%271')), "' or '1'='1 must still error");
        self::assertTrue($this->hasSqlError($this->sqlError('q=1%20union%20select%201')), 'union select must still error');
    }

    public function test_marker_present_and_fingerprint_safe(): void
    {
        for ($s = 0; $s < 300; $s++) {
            $b = (string) $this->sqlError('q=%27%22', [], (string) $s)->body;
            self::assertStringContainsString('You have an error in your SQL syntax', $b, "seed {$s} marker");
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist run");
        }
    }
}
