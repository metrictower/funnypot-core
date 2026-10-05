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
 * FP-0382: Splunk Enterprise PostgreSQL recovery sidecar auth-bypass decoy (CVE-2026-20253, CISA KEV).
 * POST /en-US/splunkd/__raw/v1/postgres/recovery/{backup,restore} answers unauthenticated with the
 * authentic Splunkd REST validation-error envelope (status 400), confirming reachability without writing
 * any file. Inert; match on path+POST only; GET does not serve.
 */
final class SplunkPostgresRecoveryDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private const EXPLOIT_BODY = '{"database":"search_metadata","backupFile":"../../../../../../tmp/poc"}';

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

    private function post(string $path, ?string $body = self::EXPLOIT_BODY): ?\Funnypot\Core\SynthesizedResponse
    {
        return $this->engine()->respond(new RequestContext('POST', $path, '', ['Content-Type' => 'application/json'], $body, 'x.test'));
    }

    public function test_backup_endpoint_answers_unauthenticated_with_splunkd_error(): void
    {
        $r = $this->post('/en-US/splunkd/__raw/v1/postgres/recovery/backup');
        self::assertNotNull($r);
        self::assertSame(400, $r->status, 'authored Splunkd validation-error envelope (not a 5xx fault)');
        self::assertStringContainsString('application/json', (string) ($r->headers['Content-Type'] ?? ''));
        $b = (string) $r->body;
        self::assertStringContainsString('backupFile is a required field', $b);
        self::assertStringContainsString('"type":"ERROR"', $b, 'genuine Splunk REST error envelope shape');
    }

    public function test_restore_endpoint_also_answers(): void
    {
        $r = $this->post('/en-US/splunkd/__raw/v1/postgres/recovery/restore');
        self::assertNotNull($r);
        self::assertSame(400, $r->status);
        self::assertStringContainsString('"type":"ERROR"', (string) $r->body);
    }

    public function test_splunk_wins_its_path_over_generic_lfi(): void
    {
        // Priority 20 (below the injection band) so the Splunk rule wins its own path even against a
        // traversal/etc-passwd-laced backupFile — a Splunk endpoint must return a Splunk envelope, not a
        // generic passwd body (the store-miss precedence closed by the low priority; FP-0554 = structural).
        $r = $this->post('/en-US/splunkd/__raw/v1/postgres/recovery/backup', '{"backupFile":"../../../../etc/passwd"}');
        self::assertNotNull($r);
        self::assertStringContainsString('"type":"ERROR"', (string) $r->body, 'Splunk envelope wins its path');
        self::assertStringNotContainsString('root:x:0:0', (string) $r->body, 'the generic LFI decoy must not win on the Splunk path');
    }

    public function test_get_does_not_serve(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/en-US/splunkd/__raw/v1/postgres/recovery/backup', '', [], null, 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringNotContainsString('backupFile is a required field', $b, 'the sidecar bypass is POST-only');
    }

    public function test_no_request_byte_reflected(): void
    {
        // Static envelope — the attacker's backupFile/database must never echo into the body.
        $r = $this->post('/en-US/splunkd/__raw/v1/postgres/recovery/backup', '{"database":"Zsplunksentinel55Z","backupFile":"../../Zsplunksentinel55Z"}');
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('backupFile is a required field', $b);
        self::assertStringNotContainsString('Zsplunksentinel55Z', $b);
    }
}
