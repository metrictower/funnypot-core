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
 * FP-0455: Langflow unauthenticated code-execution decoy (CVE-2025-3248, CISA KEV). owns_path override on
 * POST /api/v1/validate/code serving the command output inside the real validate/code envelope
 * (function.errors[]): passwd-style for the nuclei KEV probe, uid= for a whoami/id probe. As the owns_path
 * owner of a corpus-keyed path it wins via the matchOnOwnedPath Tier-1 override (FP-0547) over the generic
 * LFI/cmdi rules on the exploit's command-bearing body, regardless of its priority. Inert; no byte reflected.
 */
final class LangflowRceDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $ceiling = 'high'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling, 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function post(string $body, string $ceiling = 'high'): ?object
    {
        return $this->engine($ceiling)->respond(new RequestContext('POST', '/api/v1/validate/code', '', ['Content-Type' => 'application/json'], $body, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_passwd_probe_confirms_via_function_errors(): void
    {
        // A nuclei-KEV-style probe that reads /etc/passwd (no id/whoami token) -> passwd output.
        foreach (['high', 'critical'] as $ceil) {
            $b = $this->body($this->post('{"code":"@exec\ndef x():\n open(\'/etc/passwd\').read()"}', $ceil));
            self::assertStringContainsString('root:x:0:0', $b, "passwd confirmation at {$ceil}");
            self::assertStringContainsString('"function"', $b, 'real validate/code envelope');
            self::assertNotNull(json_decode($b), 'valid JSON');
        }
    }

    public function test_uid_probe_confirms_via_function_errors(): void
    {
        $b = $this->body($this->post('{"code":"import os\nos.system(\'id\')"}'));
        self::assertStringContainsString('uid=1000(langflow)', $b);
        self::assertStringContainsString('"function"', $b);
    }

    public function test_wins_over_cmdi_unix_on_command_bearing_body(): void
    {
        // The exploit body carries unix command markers that 41-cmdi-unix would match; the owns_path Tier-1
        // override (FP-0547) must win, serving the Langflow envelope (function.errors), NOT the cmdi uid=0(root) page.
        $b = $this->body($this->post('{"code":"import subprocess; subprocess.check_output([\'cat\',\'/etc/passwd\'])"}'));
        self::assertStringContainsString('"function"', $b, 'Langflow rule must win over 41-cmdi-unix');
        self::assertStringNotContainsString('uid=0(root)', $b, 'must not be the generic cmdi page');
    }

    public function test_non_post_and_sibling_paths_decline(): void
    {
        $g = $this->engine()->respond(new RequestContext('GET', '/api/v1/validate/code', '', [], null, 'x.test'));
        self::assertStringNotContainsString('function', $this->body($g));
    }

    public function test_submitted_code_is_never_reflected(): void
    {
        $marker = 'Zlangflowsentinel88Z';
        $b = $this->body($this->post('{"code":"@exec(\'' . $marker . '\')"}'));
        self::assertStringContainsString('"function"', $b);
        self::assertStringNotContainsString($marker, $b);
    }
}
