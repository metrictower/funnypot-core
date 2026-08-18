<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * Attack-class emulation is now data (compiled funnypot templates), not hand-coded
 * signatures. These parity cases pin that the compiled rules reproduce every class the
 * old Attack\Signature suite covered.
 */
final class AttackEmulatorTest extends TestCase
{
    private function emulate(string $path, string $query = '', ?string $body = null, array $headers = []): ?object
    {
        return TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php')
            ->emulate(new RequestContext('GET', $path, $query, $headers, $body));
    }

    public function test_lfi_returns_fake_passwd(): void
    {
        $r = $this->emulate('/download', 'file=../../../../etc/passwd');
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
        self::assertSame(['attack-lfi-unix'], $r->satisfies->templateIds());
    }

    public function test_lfi_matches_url_encoded_traversal(): void
    {
        $r = $this->emulate('/x', 'p=..%2f..%2f..%2fetc%2fpasswd');
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
    }

    public function test_sqli_returns_sql_error(): void
    {
        $r = $this->emulate('/item', "id=1' OR '1'='1");
        self::assertNotNull($r);
        self::assertStringContainsString('SQL syntax', $r->body);
        self::assertSame(['attack-sqli'], $r->satisfies->templateIds());
    }

    public function test_command_injection_returns_id_output(): void
    {
        $r = $this->emulate('/ping', 'host=127.0.0.1;id');
        self::assertNotNull($r);
        self::assertStringContainsString('uid=0(root)', $r->body);
        self::assertSame(['attack-cmdi-unix'], $r->satisfies->templateIds());
    }

    public function test_ssti_returns_evaluated_result(): void
    {
        self::assertStringContainsString('49', $this->emulate('/hello', 'name={{7*7}}')->body);
        self::assertStringContainsString('7777777', $this->emulate('/hello', "name={{7*'7'}}")->body);
    }

    public function test_xss_reflects_only_the_payload(): void
    {
        $payload = '<script>alert(document.domain)</script>';
        $r = $this->emulate('/search', 'q=' . $payload);
        self::assertNotNull($r);
        self::assertStringContainsString($payload, $r->body);
        self::assertSame(['attack-xss'], $r->satisfies->templateIds());
    }

    public function test_benign_request_is_not_an_attack(): void
    {
        self::assertNull($this->emulate('/search', 'q=hello world'));
        self::assertNull($this->emulate('/about', ''));
    }

    public function test_shellshock_in_a_header_returns_passwd(): void
    {
        $r = $this->emulate('/cgi-bin/status', '', null, ['User-Agent' => '() { :;}; echo; /bin/cat /etc/passwd']);
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
        self::assertSame(['attack-shellshock'], $r->satisfies->templateIds());
    }

    public function test_struts_ognl_in_content_type_returns_id(): void
    {
        $ct = "%{(#_='multipart/form-data').(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}";
        $r = $this->emulate('/upload.action', '', null, ['Content-Type' => $ct]);
        self::assertNotNull($r);
        self::assertStringContainsString('uid=0(root)', $r->body);
        self::assertSame(['attack-struts-ognl'], $r->satisfies->templateIds());
    }

    public function test_xxe_body_returns_passwd(): void
    {
        $body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>';
        $r = $this->emulate('/api', '', $body);
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
        self::assertSame(['attack-xxe'], $r->satisfies->templateIds());
    }

    public function test_open_redirect_returns_302_to_supplied_url(): void
    {
        $r = $this->emulate('/go', 'url=https://evil.example/phish');
        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('https://evil.example/phish', $r->headers['Location']);
    }

    public function test_open_redirect_crlf_is_declined_by_header_guard(): void
    {
        // A CRLF-bearing redirect value must not become a split header — the emulator's
        // C8 guard declines it.
        self::assertNull($this->emulate('/go', 'url=https://evil.example/%0d%0aSet-Cookie:x=1'));
    }

    // --- integration through Honeypot::respond() ---

    private function inverter(array $overrides = []): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');

        return new Honeypot($store, new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            severityCeiling: $overrides['severityCeiling'] ?? 'high',
            attackEmulation: $overrides['attackEmulation'] ?? true
        ));
    }

    public function test_respond_emulates_attack_on_unmatched_path(): void
    {
        // /nope is not a compiled route, but the LFI payload triggers attack emulation.
        $resp = $this->inverter()->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd'));
        self::assertNotNull($resp);
        self::assertStringContainsString('root:x:0:0', $resp->body);
    }

    public function test_attack_emulation_off_by_default(): void
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
        $inv = new Honeypot($store, new Config(mode: 'respond', gate: static fn (RequestContext $r): bool => true));

        self::assertNull($inv->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd')));
    }

    public function test_severity_ceiling_gates_fake_rce(): void
    {
        // command-injection is 'critical'; the default 'high' ceiling refuses to fake it.
        self::assertNull($this->inverter()->respond(new RequestContext('GET', '/ping', 'x=;id')));
        // raising the ceiling lets it through.
        $resp = $this->inverter(['severityCeiling' => 'critical'])->respond(new RequestContext('GET', '/ping', 'x=;id'));
        self::assertNotNull($resp);
        self::assertStringContainsString('uid=0(root)', $resp->body);
    }
}
