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
 * FP-0597: the unix command-injection oracle (41-cmdi-unix) branches each recon command to COHERENT
 * seeded output (the shared CannedData set), instead of serving uid=0 for everything. `;id` and a bare
 * injection keep uid=0 (the RCE-confirm marker); `;cat /etc/passwd` is still answered by the LFI rule.
 */
final class CmdiReconCoherenceTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index;

    private function engine(): Honeypot
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return new Honeypot(
            new PhpArrayStore(self::$index),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
    }

    private function body(string $query): string
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/a', $query, [], null, 'x.test'));
        self::assertNotNull($r);

        return (string) $r->body;
    }

    public function test_id_and_bare_injection_still_return_uid(): void
    {
        self::assertStringContainsString('uid=0(root)', $this->body('x=;id'));
    }

    public function test_ls_returns_a_listing_not_a_uid(): void
    {
        $b = $this->body('x=;ls%20-la');
        self::assertStringNotContainsString('uid=0', $b, 'ls must not print a uid line');
    }

    public function test_ps_returns_a_process_table(): void
    {
        $b = $this->body('x=;ps%20aux');
        self::assertStringContainsString('USER', $b);
        self::assertStringNotContainsString('uid=0', $b);
    }

    public function test_pwd_returns_a_working_directory(): void
    {
        self::assertStringStartsWith('/var/www/', $this->body('x=;pwd'));
    }

    public function test_uname_returns_a_full_kernel_line(): void
    {
        $b = $this->body('x=;uname%20-a');
        self::assertStringStartsWith('Linux ', $b);
        self::assertStringContainsString('x86_64', $b);
        self::assertStringNotContainsString('uid=0', $b);
    }

    public function test_env_returns_key_value_pairs_not_a_uid(): void
    {
        $b = $this->body('x=;env');
        self::assertStringContainsString('PATH=', $b);
        self::assertStringNotContainsString('uid=0', $b, 'env must not print a uid line');
    }

    public function test_benign_env_param_is_not_a_command(): void
    {
        // The (?![=\w]) guard: `&env=prod` is a param key, not a shell `;env`, so it must not fold an attack.
        $r = $this->engine()->respond(new RequestContext('GET', '/a', 'a=1&env=prod', [], null, 'x.test'));
        self::assertTrue($r === null || strpos((string) $r->body, 'PATH=') === false, 'a benign env= param must not serve env output');
    }

    public function test_cat_passwd_is_still_answered_by_the_lfi_rule(): void
    {
        // Precedence unchanged: `;cat /etc/passwd` is owned by attack-lfi-unix, not the cmdi oracle.
        self::assertStringContainsString('root:x:0:0:', $this->body('x=;cat%20/etc/passwd'));
    }

    // --- Windows cmdi oracle (40-cmdi-windows): dir/systeminfo no longer serve the ipconfig body ---

    public function test_windows_dir_returns_a_listing_not_ipconfig(): void
    {
        $b = $this->body('x=&dir');
        self::assertStringContainsString('Directory of', $b);
        self::assertStringNotContainsString('Windows IP Configuration', $b, 'dir must not return the ipconfig body');
    }

    public function test_windows_systeminfo_returns_a_host_summary(): void
    {
        $b = $this->body('x=&systeminfo');
        self::assertStringContainsString('Host Name:', $b);
        self::assertStringContainsString('OS Name:', $b);
        self::assertStringNotContainsString('Windows IP Configuration', $b);
    }

    public function test_windows_ipconfig_still_returns_ipconfig(): void
    {
        self::assertStringContainsString('Windows IP Configuration', $this->body('x=&ipconfig'));
    }
}
