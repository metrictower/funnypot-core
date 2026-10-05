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
 * FP-0431: error-based SQLi EXTRACTION oracle (MySQL). The function-based extraction vectors
 * (EXTRACTVALUE/UPDATEXML/GTID_SUBSET/JSON_KEYS/EXP(~…)/(x*1E308)) get the authentic MySQL
 * `XPATH syntax error: '~<value>~'` runtime-error frame embedding persona-coherent SYNTHETIC schema, so a
 * tool confirms error-based SQLi and extracts a FAKE database. The branch keys on what the sub-select
 * targets (version/user/table/column/count/credential), default = the current database. Canned/seeded:
 * no attacker byte is reflected, never 500. Engine memoized per seed.
 */
final class SqlErrorExtractionOracleTest extends TestCase
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

    private function probe(string $payload, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', '/p.php', 'x=' . rawurlencode($payload), [], null, 'x.test'));
    }

    private function frame(?object $r): ?string
    {
        if ($r === null || preg_match("/XPATH syntax error: '([^']*)'/", (string) $r->body, $m) !== 1) {
            return null;
        }

        return $m[1];
    }

    public function test_extraction_vectors_serve_the_xpath_error_frame_at_200(): void
    {
        $vectors = [
            'id=1 AND extractvalue(1,concat(0x7e,version()))',
            'id=1 AND updatexml(1,concat(0x7e,current_user()),1)',
            'id=1 AND extractvalue(1,concat(0x7e,(select table_name from information_schema.tables limit 1)))',
            'id=1 OR gtid_subset(concat(0x7e,(select database())),1)',
            'id=1 AND exp(~(select*from(select user())x))',
        ];
        foreach ($vectors as $pl) {
            $r = $this->probe($pl);
            self::assertNotNull($r, "{$pl} must serve");
            self::assertSame(200, $r->status, "{$pl} must never 5xx");
            self::assertNotNull($this->frame($r), "{$pl} must carry the XPATH error frame");
        }
    }

    public function test_branch_targets_coherent_schema_elements(): void
    {
        self::assertStringContainsString('ubuntu', (string) $this->frame($this->probe('x AND extractvalue(1,concat(0x7e,version()))')), 'version vector → a MySQL version banner');
        self::assertStringContainsString('@localhost', (string) $this->frame($this->probe('x AND updatexml(1,concat(0x7e,current_user()),1)')), 'user vector → user@localhost');
        self::assertStringStartsWith('~*', (string) $this->frame($this->probe('x AND extractvalue(1,concat(0x7e,(select password from users limit 1)))')), 'credential vector → a *HEX password-hash shape');
        $tbl = (string) $this->frame($this->probe('x AND extractvalue(1,concat(0x7e,(select table_name from information_schema.tables limit 1)))'));
        self::assertNotSame('', $tbl, 'table vector → a table name');
    }

    public function test_default_case_returns_the_current_database(): void
    {
        // `SELECT database()` is the usual first extraction and the branch fallback.
        $f = (string) $this->frame($this->probe('id=1 AND extractvalue(1,concat(0x7e,database()))'));
        self::assertStringStartsWith('~', $f, 'the database name is delimited by the MySQL 0x7e frame');
    }

    public function test_benign_and_plain_sqli_do_not_hit_this_oracle(): void
    {
        self::assertNull($this->frame($this->probe('hello world')), 'a benign query must not get an XPATH error');
        // A plain syntax-breaker / union carries no extraction function → still 50-sqli, never this XPATH frame.
        self::assertNull($this->frame($this->probe("1' or '1'='1")), "plain or-1=1 stays with the generic 50-sqli");
        self::assertNull($this->frame($this->probe('1 union select 1,2,3')), 'union select stays with the generic 50-sqli');
    }

    public function test_no_attacker_byte_is_reflected(): void
    {
        $r = $this->probe('1 AND extractvalue(1,concat(0x7e,(select ZCANARYMARKERZ)))');
        self::assertNotNull($r);
        self::assertStringNotContainsString('ZCANARYMARKERZ', (string) $r->body, 'the extraction frame is canned, never reflects the payload');
    }

    public function test_marker_present_and_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 300; $s++) {
            foreach (['x AND extractvalue(1,concat(0x7e,version()))',
                'x AND extractvalue(1,concat(0x7e,(select password from users limit 1)))',
                'x AND extractvalue(1,concat(0x7e,(select table_name from information_schema.tables limit 1)))'] as $pl) {
                $b = (string) $this->probe($pl, (string) $s)->body;
                self::assertStringContainsString('XPATH syntax error', $b, "seed {$s} marker");
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist run: {$b}");
            }
        }
    }
}
