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
 * FP-0416: UNION-based SQLi extraction oracle (Waymap db_fetcher UNION mode). A UNION SELECT wrapping a
 * metadata target in the 0x7e tilde delimiter (or an information_schema enum) gets a believable SUCCESS page
 * embedding ~<synthetic>~, so the tool's extract_between_delimiters(text,'~','~') confirms + extracts a fake
 * database — where before it hit 50-sqli's generic 1064 error (no ~value~). Complements the error-based
 * oracle (FP-0431). Canned/persona-coherent, no attacker byte reflected, never 500.
 */
final class SqlUnionExtractionOracleTest extends TestCase
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

    private function probe(string $payload, string $seed = 'fixed'): object
    {
        $r = $this->engine($seed)->respond(new RequestContext('GET', '/p.php', 'id=' . rawurlencode($payload), [], null, 'x.test'));
        self::assertNotNull($r);

        return $r;
    }

    private function delimited(object $r): ?string
    {
        return preg_match('/~([^~]*)~/', (string) $r->body, $m) === 1 ? $m[1] : null;
    }

    public function test_union_tilde_extraction_reflects_a_delimited_value_at_200(): void
    {
        foreach ([
            '-1 UNION SELECT CONCAT(0x7e,version(),0x7e)',
            '-1 union all select concat(0x7e,database(),0x7e),2',
            '-1 UNION SELECT CONCAT(0x7e,current_user(),0x7e)',
            '-1 UNION SELECT table_name FROM information_schema.tables',
            '-1 UNION SELECT column_name FROM information_schema.columns',
            '-1 UNION SELECT schema_name FROM information_schema.schemata',
        ] as $pl) {
            $r = $this->probe($pl);
            self::assertSame(200, $r->status, "{$pl} must be 200, never 5xx");
            self::assertSame('attack-sqli-union-extraction', $r->servedBy->ruleId ?? null, "{$pl} must hit the UNION oracle");
            self::assertNotNull($this->delimited($r), "{$pl} must embed a ~delimited~ value for extract_between_delimiters");
        }
    }

    public function test_branch_targets_coherent_schema_elements(): void
    {
        self::assertStringContainsString('ubuntu', (string) $this->delimited($this->probe('-1 UNION SELECT CONCAT(0x7e,@@version,0x7e)')), 'version → a MySQL banner');
        self::assertStringContainsString('@localhost', (string) $this->delimited($this->probe('-1 UNION SELECT CONCAT(0x7e,user(),0x7e)')), 'user → user@host');
        $tbl = (string) $this->delimited($this->probe('-1 UNION SELECT table_name FROM information_schema.tables'));
        self::assertNotSame('', $tbl, 'tables → a table name');
    }

    public function test_plain_union_without_tilde_or_schema_falls_to_the_generic_sqli(): void
    {
        $r = $this->probe('-1 union select 1,2,3');
        self::assertSame('attack-sqli', $r->servedBy->ruleId ?? null, 'a plain union (no 0x7e / information_schema) stays with 50-sqli');
        self::assertNull($this->delimited($r), 'the generic error carries no ~delimited~ value');
    }

    public function test_no_attacker_byte_is_reflected(): void
    {
        $r = $this->probe('-1 UNION SELECT CONCAT(0x7e,ZCANARYZ,0x7e) FROM information_schema.tables');
        self::assertStringNotContainsString('ZCANARYZ', (string) $r->body, 'the delimited value is canned, never the raw payload');
    }

    public function test_fingerprint_safe_across_seeds(): void
    {
        for ($s = 0; $s < 200; $s++) {
            foreach (['-1 UNION SELECT CONCAT(0x7e,version(),0x7e)',
                '-1 UNION SELECT table_name FROM information_schema.tables'] as $pl) {
                $b = (string) $this->probe($pl, (string) $s)->body;
                self::assertStringContainsString('~', $b, "seed {$s} marker");
                self::assertSame(0, preg_match('/\b9\d{5}\b/', $b), "seed {$s} denylist run");
            }
        }
    }
}
