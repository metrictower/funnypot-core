<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\RequestContext;
use Funnypot\Template\DirectiveRenderer;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

final class TemplateEngineTest extends TestCase
{
    private function probe(string $method, string $path, string $query = '', ?string $body = null, array $headers = []): ?object
    {
        $emu = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');

        return $emu->emulate(new RequestContext($method, $path, $query, $headers, $body));
    }

    // --- the compiled attack templates, interpreted at runtime ---

    public function test_shellshock_header_template(): void
    {
        $r = $this->probe('GET', '/cgi-bin/x', '', null, ['User-Agent' => '() { :;}; echo; /bin/cat /etc/passwd']);
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
        self::assertSame(['attack-shellshock'], $r->satisfies->templateIds());
    }

    public function test_phpunit_computed_md5_template(): void
    {
        // A NEW emulation authored purely as a template: compute md5 of the probe arg.
        $r = $this->probe('POST', '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '', '<?php echo md5(1); ?>');
        self::assertNotNull($r);
        self::assertSame(md5('1'), trim($r->body));
        self::assertSame(['attack-phpunit-rce'], $r->satisfies->templateIds());
    }

    public function test_xxe_body_template(): void
    {
        $body = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]><r>&e;</r>';
        $r = $this->probe('POST', '/api', '', $body);
        self::assertNotNull($r);
        self::assertStringContainsString('root:x:0:0', $r->body);
    }

    public function test_sqli_template(): void
    {
        $r = $this->probe('GET', '/item', "id=1' OR '1'='1");
        self::assertNotNull($r);
        self::assertStringContainsString('SQL syntax', $r->body);
    }

    public function test_open_redirect_template_reflects_302(): void
    {
        $r = $this->probe('GET', '/go', 'url=https://evil.example/phish');
        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('https://evil.example/phish', $r->headers['Location']);
    }

    public function test_open_redirect_crlf_declined(): void
    {
        // The Location renders {{urldecode:match.1}} — an encoded CRLF becomes real and the
        // header guard declines the whole response.
        self::assertNull($this->probe('GET', '/go', 'url=https://evil.example/%0d%0aSet-Cookie:x=1'));
    }

    public function test_benign_request_no_match(): void
    {
        self::assertNull($this->probe('GET', '/about', 'q=hello'));
    }

    // --- backlog attack-class additions ---

    public function test_confluence_ognl_sets_cmd_response_header(): void
    {
        $r = $this->probe('GET', '/wiki/%24%7B(%23a%3D%40java.lang.Runtime%40getRuntime().exec(%22id%22))%7D');
        self::assertNotNull($r);
        self::assertSame('uid=0(root) gid=0(root) groups=0(root)', $r->headers['X-Cmd-Response']);
        self::assertSame(['attack-confluence-26134'], $r->satisfies->templateIds());
    }

    public function test_phpcgi_source_disclosure(): void
    {
        $r = $this->probe('GET', '/index.php', '-s');
        self::assertNotNull($r);
        self::assertStringContainsString('<span style', $r->body);
        self::assertSame(['attack-phpcgi-1823'], $r->satisfies->templateIds());
    }

    public function test_lfi_shadow_group_environ_smbconf_serve_the_right_file(): void
    {
        self::assertStringContainsString(':0:99999:7:::', $this->probe('GET', '/x', 'f=../../etc/shadow')->body);
        self::assertStringContainsString('root:x:0:', $this->probe('GET', '/x', 'f=../../etc/group')->body);
        self::assertStringContainsString('PATH=', $this->probe('GET', '/x', 'f=../../proc/self/environ')->body);
        self::assertStringContainsString('[global]', $this->probe('GET', '/vpn/../vpns/cfg/smb.conf')->body);
        // The generic traversal rule still serves passwd when no specific file is named.
        self::assertStringContainsString('root:x:0:0', $this->probe('GET', '/x', 'f=../../etc/passwd')->body);
    }

    public function test_glastopf_php_injection_probe(): void
    {
        $r = $this->probe('POST', '/', '', "[php]system('id')[/php]");
        self::assertNotNull($r);
        self::assertStringContainsString('uid=0(root)', $r->body);
        self::assertSame(['attack-php-glastopf'], $r->satisfies->templateIds());
    }

    // --- researched CVE / product emulators ---

    public function test_thinkphp_returns_phpinfo(): void
    {
        $r = $this->probe('GET', '/index.php', 's=/index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo');
        self::assertNotNull($r);
        self::assertStringContainsString('phpinfo()', $r->body);
        self::assertSame(['attack-thinkphp-rce'], $r->satisfies->templateIds());
    }

    public function test_owncloud_graphapi_leaks_env(): void
    {
        $r = $this->probe('GET', '/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php');
        self::assertNotNull($r);
        self::assertStringContainsString('OWNCLOUD_ADMIN_PASSWORD', $r->body);
    }

    public function test_f5_icontrol_returns_runstate(): void
    {
        $r = $this->probe('POST', '/mgmt/tm/util/bash', '', '{"utilCmdArgs":"-c id"}');
        self::assertNotNull($r);
        self::assertStringContainsString('tm:util:bash:runstate', $r->body);
    }

    public function test_fortios_auth_bypass_needs_forwarded_header(): void
    {
        // The Forwarded header is required — a plain probe must NOT trigger it.
        self::assertNull($this->probe('GET', '/api/v2/cmdb/system/admin'));
        $r = $this->probe('GET', '/api/v2/cmdb/system/admin', '', null, ['Forwarded' => 'for=1.2.3.4;by=127.0.0.1']);
        self::assertNotNull($r);
        self::assertStringContainsString('super_admin', $r->body);
    }

    public function test_webshell_panel_on_filename_and_cmd_param(): void
    {
        self::assertStringContainsString('uid=33(www-data)', $this->probe('GET', '/c99.php')->body);
        self::assertStringContainsString('uid=33(www-data)', $this->probe('GET', '/x', 'cmd=id')->body);
    }

    public function test_imds_returns_fake_credentials(): void
    {
        $r = $this->probe('GET', '/latest/meta-data/iam/security-credentials/webrole');
        self::assertNotNull($r);
        self::assertStringContainsString('AccessKeyId', $r->body);
        self::assertStringContainsString('SecretAccessKey', $r->body);
    }

    // --- the bounded directive renderer ---

    public function test_renderer_canned_and_compute(): void
    {
        $rr = new DirectiveRenderer();
        self::assertStringContainsString('root:x:0:0', $rr->render('{{canned.passwd}}'));
        self::assertSame(md5('funnypot'), $rr->render('{{compute.md5:match.1}}', ['0' => 'x', '1' => 'funnypot']));
        self::assertSame('payload=abc', $rr->render('payload={{match.1}}', ['0' => 'z', '1' => 'abc']));
    }

    public function test_renderer_fakehex_is_seeded_and_sized(): void
    {
        $rr = new DirectiveRenderer();
        $a = $rr->render('{{fakeHex:16}}', [], 42);
        $b = $rr->render('{{fakeHex:16}}', [], 42);
        $c = $rr->render('{{fakeHex:16}}', [], 99);
        self::assertSame(16, strlen($a));
        self::assertSame($a, $b);       // deterministic per seed
        self::assertNotSame($a, $c);    // varies by seed
    }

    public function test_renderer_alternative_falls_through(): void
    {
        $rr = new DirectiveRenderer();
        // canary missing -> falls through to fakeHex.
        $out = $rr->render('{{canary.aws_key | fakeHex:20}}', [], 7);
        self::assertSame(20, strlen($out));
        // canary present -> used.
        $out2 = $rr->render('{{canary.aws_key | fakeHex:20}}', [], 7, ['aws_key' => 'AKIA-CANARY']);
        self::assertSame('AKIA-CANARY', $out2);
    }

    public function test_reflected_directive_stays_literal(): void
    {
        // The never-execute invariant: an attacker payload reflected via {{match.1}} that itself
        // contains a directive is inserted ONCE and never re-scanned. Braces survive as literal
        // text; no canned marker is ever produced from attacker input.
        $rr = new DirectiveRenderer();
        $out = $rr->render('echo {{match.1}}', ['0' => 'x', '1' => '{{canned.passwd}}']);
        self::assertSame('echo {{canned.passwd}}', $out);
        self::assertStringNotContainsString('root:x:0:0', $out);
    }

    public function test_named_fake_is_reusable_and_independent(): void
    {
        $rr = new DirectiveRenderer();
        // Same name -> same value (one fake secret can appear twice); different name -> independent.
        $out = $rr->render('{{fake.dbpass:hex:24}}:{{fake.dbpass:hex:24}}:{{fake.apikey:hex:24}}', [], 5);
        [$a, $b, $c] = explode(':', $out);
        self::assertSame(24, strlen($a));
        self::assertSame($a, $b);
        self::assertNotSame($a, $c);
    }

    public function test_brace_escape(): void
    {
        $rr = new DirectiveRenderer();
        // A page that must contain real {{ }} (e.g. an Angular/Jinja mock) escapes them.
        self::assertSame('{{ user.name }}', $rr->render('{{{{ user.name }}}}'));
    }

    public function test_pick_is_seeded(): void
    {
        $rr = new DirectiveRenderer();
        $a = $rr->render('{{pick:red,green,blue}}', [], 3);
        self::assertContains($a, ['red', 'green', 'blue']);
        self::assertSame($a, $rr->render('{{pick:red,green,blue}}', [], 3));
    }

    public function test_hex_directive_emits_raw_bytes_including_high_bytes(): void
    {
        $rr = new DirectiveRenderer();
        // Expands to the raw bytes 0xff 0x00 — the whole point is bytes >= 0x80 survive intact,
        // where the YAML \xNN transport would UTF-8-widen 0xff to two bytes.
        self::assertSame("\xff\x00", $rr->render('{{hex:ff00}}'));
        self::assertSame(2, strlen($rr->render('{{hex:ff00}}')));
        // Interleaved with literal ASCII, so a binary frame can carry matcher substrings verbatim.
        self::assertSame("A\xffB", $rr->render('A{{hex:ff}}B'));
    }

    public function test_hex_directive_rejects_odd_and_garbage_input(): void
    {
        $rr = new DirectiveRenderer();
        self::assertSame('', $rr->render('{{hex:abc}}'));    // odd digit count -> no partial byte
        self::assertSame('', $rr->render('{{hex:zzzz}}'));   // no hex digits at all
        self::assertSame('', $rr->render('{{hex:}}'));       // empty
        // Non-hex separators are stripped, leaving an even run of valid digits.
        self::assertSame("\xab\xcd", $rr->render('{{hex:ab:cd}}'));
    }
}
