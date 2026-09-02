<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
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

    public function test_lfi_hostname_returns_a_hostname_not_passwd(): void
    {
        // The bug this pins: /etc/hostname used to fall through to a passwd/uid-shaped body.
        $r = $this->emulate('/download', 'file=../../../../etc/hostname');
        self::assertNotNull($r);
        self::assertSame(['attack-lfi-hostname'], $r->satisfies->templateIds());
        // The hostname is now per-deploy seeded (FP-0277): assert the single-line shape, not a fixed
        // literal (`web-prod-01` was the fleet-constant tell and is not a cross-fleet scanner marker).
        self::assertSame(1, preg_match('/^[a-z0-9][a-z0-9.-]{1,62}$/', trim($r->body)), $r->body);
        self::assertStringNotContainsString('root:x:0:0', $r->body);
    }

    public function test_lfi_ssh_key_returns_inert_pem_not_passwd(): void
    {
        // /root/.ssh/id_rsa used to return passwd content — a clear format-mismatch tell.
        $r = $this->emulate('/download', 'file=../../../root/.ssh/id_rsa');
        self::assertNotNull($r);
        self::assertSame(['attack-lfi-sshkey'], $r->satisfies->templateIds());
        self::assertStringContainsString('-----BEGIN OPENSSH PRIVATE KEY-----', $r->body);
        self::assertStringContainsString('-----END OPENSSH PRIVATE KEY-----', $r->body);
        self::assertStringNotContainsString('root:x:0:0', $r->body);

        // Inert: the base64 body is well-formed but decodes to no OpenSSH key structure, so it
        // authenticates nowhere (a real key's blob begins with the magic "openssh-key-v1\0").
        preg_match('/-----BEGIN OPENSSH PRIVATE KEY-----\n(.*)\n-----END/s', $r->body, $m);
        $blob = base64_decode(str_replace("\n", '', $m[1] ?? ''), true);
        self::assertNotFalse($blob, 'key body must be valid base64');
        self::assertStringStartsNotWith("openssh-key-v1\0", $blob);
    }

    public function test_lfi_passwd_traversal_still_returns_passwd(): void
    {
        $r = $this->emulate('/download', 'file=../../../../etc/passwd');
        self::assertNotNull($r);
        self::assertSame(['attack-lfi-unix'], $r->satisfies->templateIds());
        self::assertStringContainsString('root:x:0:0', $r->body);
    }

    public function test_phpcgi_source_varies_by_requested_script(): void
    {
        // Byte-identical source across every path was a canned-response tell; the fake source now
        // names the requested .php script, so two different scripts return different bodies.
        $a = $this->emulate('/wp-login.php', '-s');
        $b = $this->emulate('/config.php', '-s');
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertStringContainsString('wp-login.php', $a->body);
        self::assertStringContainsString('config.php', $b->body);
        self::assertNotSame($a->body, $b->body);
    }

    public function test_command_injection_matches_double_url_encoded(): void
    {
        // WAF-evasion double-encoding: %253B -> %3B -> ';'. A second decode pass recovers the payload.
        $r = $this->emulate('/ping', 'host=127.0.0.1%253Bid');
        self::assertNotNull($r);
        self::assertStringContainsString('uid=0(root)', $r->body);
        self::assertSame(['attack-cmdi-unix'], $r->satisfies->templateIds());
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

    public function test_ssti_computes_across_markers_and_operators(): void
    {
        // Every recognized template marker "renders" the arithmetic to the same integer.
        foreach (['name={{7*7}}', 'name=${7*7}', 'name=#{7*7}', 'name=${{7*7}}', 'x=<%= 7*7 %>'] as $q) {
            $r = $this->emulate('/hello', $q);
            self::assertNotNull($r, $q);
            self::assertSame(['attack-ssti-numeric'], $r->satisfies->templateIds(), $q);
            self::assertSame("49\n", $r->body, $q);
        }

        // Multi-op and randomized operands — a canned 49 could not fake these.
        self::assertSame("50\n", $this->emulate('/hello', 'name={{7*7+1}}')->body);
        self::assertSame("1337\n", $this->emulate('/hello', 'name={{1338-1}}')->body);
        self::assertSame("20\n", $this->emulate('/hello', 'name={{ (2+3) * 4 }}')->body);
    }

    public function test_ssti_non_arithmetic_payload_does_not_execute(): void
    {
        // Hostile object-access SSTI payloads must never render a value and never error — the SSTI
        // decoy simply does not fire (no attack fake), so the request falls through unremarkably.
        self::assertNull($this->emulate('/hello', 'name={{config}}'));
        self::assertNull($this->emulate('/hello', "name={{7*''.__class__}}"));
        self::assertNull($this->emulate('/hello', 'name={{request.application}}'));
    }

    public function test_ssti_unsafe_arithmetic_degrades_without_500(): void
    {
        // Division by zero and overflow: the rule matches but the evaluator declines, so the inert
        // base page serves at 200 — never a 500 (which would itself be a tell).
        foreach (['name={{1/0}}', 'name={{99999999999999*2}}'] as $q) {
            $r = $this->emulate('/hello', $q);
            self::assertNotNull($r, $q);
            self::assertSame(200, $r->status, $q);
            self::assertStringNotContainsString('49', $r->body, $q);
        }
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
            'respond',                                                        // mode
            static function (RequestContext $r): bool { return true; },       // gate
            'matched-only',                                                   // pathScope
            null,                                                             // personaSeed
            'coherent',                                                       // personaBreadth
            \Funnypot\Core\Response\Style::MINIMAL,                                // responseStyle
            $overrides['severityCeiling'] ?? 'high',                          // severityCeiling
            65536,                                                            // maxBodyBytes
            0,                                                                // latencyMs
            0,                                                                // latencyJitterMs
            $overrides['attackEmulation'] ?? true                            // attackEmulation
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
        $inv = new Honeypot($store, new Config('respond', static function (RequestContext $r): bool { return true; }));

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
