<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The literal pre-filter (compiler emits `lit`/`lit_in`/`lit_ci`; matchRule() skips a rule whose
 * required literal is absent) is a pure speedup: it must return the IDENTICAL match — same rule id
 * and same captures — as an unfiltered pass for every request. These tests pin that invariant by
 * running the shipped rules two ways over a representative request set:
 *   - active:    the compiled rules, pre-filter live;
 *   - reference: the same rules with lit/lit_in/lit_ci stripped, so the pre-filter never fires.
 * Any divergence means a literal was wrongly treated as required and a real match got skipped.
 */
final class AttackLiteralPrefilterTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private static $rules = [];

    public static function setUpBeforeClass(): void
    {
        $rules = require __DIR__ . '/../resources/compiled/funnypot-attack.php';
        self::$rules = is_array($rules) ? $rules : [];
    }

    /** Emulator over the compiled rules, pre-filter live. */
    private function active(): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator(self::$rules);
    }

    /** Same rules with the pre-filter keys removed — the un-filtered reference. */
    private function reference(): TemplateAttackEmulator
    {
        $stripped = [];
        foreach (self::$rules as $rule) {
            unset($rule['lit'], $rule['lit_in'], $rule['lit_ci']);
            $stripped[] = $rule;
        }

        return new TemplateAttackEmulator($stripped);
    }

    /**
     * @param array{rule:array<string,mixed>,captures:array<int|string,string>}|null $m
     * @return array{id:string,captures:array<int|string,string>}|null
     */
    private static function shape(?array $m): ?array
    {
        if ($m === null) {
            return null;
        }

        return ['id' => (string) ($m['rule']['id'] ?? ''), 'captures' => $m['captures']];
    }

    /** Assert the pre-filter and the reference agree on rule id + captures for one request. */
    private function assertSameMatch(RequestContext $r, string $why): void
    {
        self::assertSame(
            self::shape($this->reference()->matchRule($r)),
            self::shape($this->active()->matchRule($r)),
            "pre-filter diverged from the un-filtered reference: {$why}"
        );
    }

    /** At least one shipped rule carries a `lit`, else this suite proves nothing. */
    public function test_some_rules_carry_a_literal(): void
    {
        $withLit = 0;
        foreach (self::$rules as $rule) {
            if (isset($rule['lit'])) {
                $withLit++;
            }
        }
        self::assertGreaterThan(0, $withLit, 'no rule got a lit — the pre-filter is inert');
    }

    /**
     * A request crafted to hit each lit-bearing rule as the first match. Asserts BOTH that the
     * reference resolves to the expected rule (the payload is a genuine hit) AND that the active
     * pre-filter still resolves to the same rule with the same captures — i.e. a rule that SHOULD
     * match is never skipped by its own literal.
     *
     * @dataProvider litRuleHits
     */
    public function test_lit_rule_hit_is_not_skipped(string $expectedId, RequestContext $r): void
    {
        $ref = self::shape($this->reference()->matchRule($r));
        self::assertNotNull($ref, "payload for {$expectedId} did not match anything in the reference");
        self::assertSame($expectedId, $ref['id'], "payload was expected to hit {$expectedId} first");

        self::assertSame($ref, self::shape($this->active()->matchRule($r)), "pre-filter skipped {$expectedId}");
    }

    /**
     * expectedRuleId => a request that hits it as first-match. Covers every rule that got a `lit`.
     *
     * @return array<string,array{0:string,1:RequestContext}>
     */
    public static function litRuleHits(): array
    {
        $g = static function (string $path, string $query = '', ?string $body = null, array $headers = []): RequestContext {
            return new RequestContext('GET', $path, $query, $headers, $body);
        };

        return [
            'confluence-26134' => ['attack-confluence-26134', $g('/x', "p=\${(#a=@java.lang.Runtime@getRuntime())}")],
            'phpcgi-4577'      => ['attack-phpcgi-4577', $g('/index.php', 'something=%add')],
            'shellshock'       => ['attack-shellshock', $g('/cgi-bin/status', '', null, ['User-Agent' => '() { :;}; echo vuln'])],
            'struts-ognl'      => ['attack-struts-ognl', $g('/upload.action', '', null, ['Content-Type' => "%{(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd))}"])],
            'phpunit-rce'      => ['attack-phpunit-rce', $g('/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php', '', '<?php md5("abc"); ?>')],
            'xxe'              => ['attack-xxe', $g('/api', '', '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>')],
            'lfi-smbconf'      => ['attack-lfi-smbconf', $g('/download', 'file=../../etc/samba/smb.conf')],
            'lfi-environ'      => ['attack-lfi-environ', $g('/download', 'file=/proc/self/environ')],
            'lfi-shadow'       => ['attack-lfi-shadow', $g('/download', 'file=/etc/shadow')],
            'lfi-group'        => ['attack-lfi-group', $g('/download', 'file=/etc/group')],
            'php-glastopf'     => ['attack-php-glastopf', $g('/index.php', '', '[php]system("id");[/php]')],
            'owncloud-49103'   => ['attack-owncloud-49103', $g('/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php')],
            'f5-1388'          => ['attack-f5-1388', $g('/mgmt/tm/util/bash', '', '{"command":"run","utilCmdArgs":"-c id"}')],
            'geoserver-36401'  => ['attack-geoserver-36401', $g('/geoserver/wms', 'x=Runtime')],
            'fortios-40684'    => ['attack-fortios-40684', $g('/api/v2/cmdb/system/admin', '', null, ['Forwarded' => 'for=127.0.0.1'])],
            'ivanti-21887'     => ['attack-ivanti-21887', $g('/api/v1/totp/user-backup-code')],
            'citrix-4966'      => ['attack-citrix-bleed-4966', $g('/oauth/idp/.well-known/openid-configuration')],
            'spring-actuator'  => ['attack-spring-actuator', $g('/actuator/env')],
            // URL-encoded traversal — the required literal must be found on the rawurldecode()
            // half of the `request` surface, exactly as the regex matches it.
            'lfi-environ-enc'  => ['attack-lfi-environ', $g('/download', 'file=%2Fproc%2Fself%2Fenviron')],
        ];
    }

    /**
     * A broad set that agreement must hold over: no-lit attack payloads, benign misses, and empty
     * inputs. (No specific rule is asserted — only that the pre-filter never changes the outcome.)
     *
     * @dataProvider parityRequests
     */
    public function test_prefilter_matches_reference(string $why, RequestContext $r): void
    {
        $this->assertSameMatch($r, $why);
    }

    /**
     * @return array<string,array{0:string,1:RequestContext}>
     */
    public static function parityRequests(): array
    {
        $g = static function (string $path, string $query = '', ?string $body = null, array $headers = []): RequestContext {
            return new RequestContext('GET', $path, $query, $headers, $body);
        };

        return [
            // no-lit attack rules (evaluated in both passes; agreement is trivial but covered).
            'phpcgi-1823'    => ['phpcgi-1823 arg injection', $g('/index.php', '-d+allow_url_include%3d1')],
            'lfi-windows'    => ['lfi windows', $g('/download', 'file=../../win.ini')],
            'lfi-unix'       => ['lfi unix traversal', $g('/download', 'file=../../../../etc/passwd')],
            'cmdi-windows'   => ['cmdi windows', $g('/ping', 'host=127.0.0.1;systeminfo')],
            'cmdi-unix'      => ['cmdi unix', $g('/ping', 'host=127.0.0.1;id')],
            'ssti-twig'      => ['ssti twig', $g('/hello', "name={{7*'7'}}")],
            'ssti-numeric'   => ['ssti numeric', $g('/hello', 'name={{7*7}}')],
            'sqli'           => ['sqli', $g('/item', "id=1' OR '1'='1")],
            'open-redirect'  => ['open redirect', $g('/go', 'url=https://evil.example/x')],
            'xss'            => ['xss', $g('/search', 'q=<script>alert(1)</script>')],
            'thinkphp'       => ['thinkphp rce', $g('/index.php', 's=/index/think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo')],
            'webshell'       => ['webshell cmd param', $g('/panel', 'cmd=whoami')],
            'cloud-imds'     => ['cloud imds', $g('/latest/meta-data/iam/security-credentials/')],
            'crs-sqli'       => ['crs sqli union', $g('/search', 'q=1 union all select username,password from users')],
            'crs-xss'        => ['crs xss onerror', $g('/p', 'x=<img src=x onerror=alert(1)>')],
            // benign misses — nothing should match either way.
            'benign-1'       => ['benign search', $g('/search', 'q=hello world')],
            'benign-2'       => ['benign about', $g('/about')],
            'benign-3'       => ['benign api', $g('/api/users', 'page=2&limit=20')],
            'benign-json'    => ['benign json body', $g('/api', '', '{"name":"alice","role":"user"}')],
            // near-misses: surface carries part of a literal but not the whole required run.
            'near-actuator'  => ['actuators plural is not /actuator$', $g('/actuators-dashboard')],
            'near-api-v2'    => ['api/v2 is not ivanti /api/v1/', $g('/api/v2/status')],
            // empty / minimal.
            'empty'          => ['empty request', $g('/')],
        ];
    }

    /** A literal present only beyond MAX_SURFACE must be treated the same by both passes. */
    public function test_oversized_surface_agrees(): void
    {
        $pad = str_repeat('a', 40000);
        // smb.conf sits past the 32 KiB cap, so neither pass may treat lfi-smbconf as a hit.
        $r = new RequestContext('GET', '/download', 'file=' . $pad . 'smb.conf');
        $this->assertSameMatch($r, 'literal beyond MAX_SURFACE');

        // A hit within the cap still resolves identically even with a large surface.
        $r2 = new RequestContext('GET', '/download', 'file=/proc/self/environ&junk=' . $pad);
        $this->assertSameMatch($r2, 'hit before the cap in a large surface');
    }

    /** Malformed bytes must not desync the two passes. */
    public function test_malformed_input_agrees(): void
    {
        $this->assertSameMatch(new RequestContext('GET', "/x\xff\xfe", "q=%\x00" . 'smb.conf'), 'binary bytes in surface');
        $this->assertSameMatch(new RequestContext('GET', '/', '', [], "\xc3\x28<!ENTITY x SYSTEM \"file:\""), 'invalid utf-8 body');
    }
}
