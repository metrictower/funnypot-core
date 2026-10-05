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
 * FP-0573: error-based SQLi EXTRACTION oracle — MSSQL / PostgreSQL / Oracle dialects (siblings of the
 * FP-0431 MySQL oracle). Each dialect's extraction vector (CONVERT/CAST AS INT; CAST AS NUMERIC /
 * ::numeric; CTXSYS.DRITHSX.SN / UTL_INADDR) serves that dialect's AUTHENTIC runtime error embedding
 * persona-coherent SYNTHETIC schema at 200, so a dialect-aware scanner confirms error-based extraction
 * against a FAKE database. Canned/seeded: no attacker byte reflected, never 5xx. Engine memoized per seed.
 */
final class MultiDialectSqlErrorOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;
    /** @var Honeypot|null */
    private static $engine;

    private function engine(): Honeypot
    {
        if (self::$engine !== null) {
            return self::$engine;
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, 'fixed');
        $cfg->attackEmulation = true;

        return self::$engine = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $payload): ?string
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/p.php', 'x=' . rawurlencode($payload), [], null, 'x.test'));

        return $r === null ? null : (string) $r->body;
    }

    private function status(string $payload): ?int
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/p.php', 'x=' . rawurlencode($payload), [], null, 'x.test'));

        return $r === null ? null : $r->status;
    }

    public function test_mssql_convert_int_serves_the_conversion_failed_error(): void
    {
        self::assertSame(200, $this->status('id=1 AND 1=CONVERT(INT,@@version)'));
        $b = $this->body('id=1 AND 1=CONVERT(INT,@@version)');
        self::assertStringContainsString('Conversion failed when converting', (string) $b);
        self::assertStringContainsString('SQL Server', (string) $b, 'the @@version target leaks a SQL Server banner');
        // credential target leaks a hash shape, not the attacker payload.
        self::assertStringContainsString('Conversion failed when converting', (string) $this->body('id=1 AND 1=CAST((SELECT password FROM users) AS INT)'));
    }

    public function test_pgsql_numeric_cast_serves_the_invalid_input_syntax_error(): void
    {
        self::assertSame(200, $this->status('id=1 AND 1=CAST(version() AS NUMERIC)'));
        self::assertStringContainsString('invalid input syntax for type numeric', (string) $this->body('id=1 AND 1=CAST(version() AS NUMERIC)'));
        self::assertStringContainsString('PostgreSQL', (string) $this->body('id=1 AND 1=CAST(version() AS NUMERIC)'), 'version() leaks a PostgreSQL banner');
        // the ::numeric cast form also fires.
        self::assertStringContainsString('invalid input syntax for type numeric', (string) $this->body('id=1 AND current_user::numeric'));
    }

    public function test_oracle_ctxsys_serves_the_ora_error(): void
    {
        self::assertSame(200, $this->status('id=1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version))'));
        $b = $this->body('id=1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version))');
        self::assertStringContainsString('ORA-20000:', (string) $b);
        self::assertStringContainsString('Oracle Database', (string) $b, 'the banner target leaks an Oracle version');
        // UTL_INADDR vector also fires.
        self::assertStringContainsString('ORA-20000:', (string) $this->body('id=1 AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))'));
    }

    public function test_no_attacker_byte_is_reflected(): void
    {
        $canary = 'ZZDIALECTZZ';
        foreach ([
            "id=1 AND 1=CONVERT(INT,(SELECT {$canary}))",
            "id=1 AND 1=CAST({$canary} AS NUMERIC)",
            "id=1 AND 1=CTXSYS.DRITHSX.SN(1,(SELECT {$canary} FROM dual))",
        ] as $pl) {
            self::assertStringNotContainsString($canary, (string) $this->body($pl), "must not reflect the canary for: {$pl}");
        }
    }

    public function test_benign_requests_do_not_serve_a_dialect_error(): void
    {
        foreach (['q=best cast iron skillet', 'price=19.99', 'name=' . rawurlencode('José'), 'note=convert to pdf'] as $q) {
            $r = $this->engine()->respond(new RequestContext('GET', '/p.php', $q, [], null, 'x.test'));
            $b = $r === null ? '' : (string) $r->body;
            self::assertStringNotContainsString('Conversion failed when converting', $b, "benign served a dialect error: {$q}");
            self::assertStringNotContainsString('invalid input syntax for type numeric', $b, "benign served a dialect error: {$q}");
            self::assertStringNotContainsString('ORA-20000:', $b, "benign served a dialect error: {$q}");
        }
    }
}
