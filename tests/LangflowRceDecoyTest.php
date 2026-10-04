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
 * FP-0455: Langflow unauthenticated code-execution decoy (CVE-2025-3248, CISA KEV). An owns_path override on
 * POST /api/v1/validate/code serves a canned Langflow validate/code response carrying the "executed"
 * command output (uid=1000(langflow)), so a scanner confirms the RCE. Inert: the submitted code is never
 * compiled/executed, no request byte reflected.
 */
final class LangflowRceDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $indexCache;

    private function engine(string $ceiling = 'high'): Honeypot
    {
        if (self::$indexCache === null) {
            self::$indexCache = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling, 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$indexCache), $cfg);
    }

    private function post(string $body = '{"code":"x"}', string $ceiling = 'high'): ?object
    {
        return $this->engine($ceiling)->respond(new RequestContext('POST', '/api/v1/validate/code', '', ['Content-Type' => 'application/json'], $body, 'x.test'));
    }

    public function test_post_returns_canned_rce_confirmation_at_embedder_ceiling(): void
    {
        $r = $this->post();
        self::assertSame(200, $r->status ?? null, 'must serve at the default high (embedder) ceiling');
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('uid=1000(langflow)', $b, 'command-output confirmation');
        self::assertNotNull(json_decode($b), 'must be valid JSON (authentic validate/code shape)');
        self::assertStringContainsString('"imports"', $b);
        self::assertSame('application/json', $r->headers['Content-Type'] ?? null);
    }

    public function test_also_serves_at_critical_ceiling(): void
    {
        self::assertStringContainsString('uid=1000(langflow)', (string) ($this->post('{"code":"y"}', 'critical')->body ?? ''));
    }

    public function test_non_post_does_not_serve_the_confirmation(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/api/v1/validate/code', '', [], null, 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringNotContainsString('uid=1000(langflow)', $b, 'only POST is the exploit shape');
    }

    public function test_submitted_code_is_never_reflected(): void
    {
        $marker = 'Zlangflowsentinel88Z';
        $b = (string) ($this->post('{"code":"@exec(\'' . $marker . '\')"}')->body ?? '');
        self::assertStringContainsString('uid=1000(langflow)', $b);
        self::assertStringNotContainsString($marker, $b, 'the submitted code must never be echoed');
    }
}
