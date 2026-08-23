<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware Grafana /grafana/login credential emulator (attack rule 100, WP-Phase-2b),
 * coherent with route 379's login shell (Grafana 10.4.2, appSubUrl /grafana). A bad-credential POST
 * is answered with the authentic static 401 `password-auth.failed` JSON body — Grafana's simplest
 * failure shape, no branching. Pins the load-bearing safety invariants: zero-reflection (the
 * submitted `user` field never surfaces in the response — the body is fully static), zero-execution
 * (the password is never read at all), never-authenticate (no Set-Cookie — Grafana's session cookie
 * is success-only), and POST-gated (any other verb misses — no route here for POST).
 */
final class GrafanaLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/grafana/login';
    private const ID = 'attack-grafana-login';
    private const EXPECTED_BODY = '{"statusCode":401,"messageId":"password-auth.failed","message":"Invalid username or password"}';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** The compiled Grafana rule alone, so an adversarial credential can't trip an earlier broad rule. */
    private function isolatedRule(): array
    {
        foreach ((require self::COMPILED) as $rule) {
            if (($rule['id'] ?? '') === self::ID) {
                return $rule;
            }
        }
        self::fail(self::ID . ' not compiled');
    }

    private function isolated(): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator([$this->isolatedRule()]);
    }

    private function body(string $user, string $pass = 'x'): string
    {
        return json_encode(['user' => $user, 'password' => $pass]);
    }

    // --- compile / ownership ------------------------------------------------------------------------

    public function test_rule_compiled_unique_and_owns_grafana_login(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains(self::ID, $ids);
        self::assertSame(1, array_count_values($ids)[self::ID], 'rule id must be unique');

        self::assertTrue($this->emulator()->ownsPath(self::PATH));
    }

    // --- basic dispatch: byte-accurate static 401 JSON --------------------------------------------

    public function test_bad_credentials_return_static_401_json(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('admin')));
        self::assertNotNull($r);
        self::assertSame(401, $r->status);
        self::assertSame('application/json', $r->headers['Content-Type']);
        self::assertSame(self::EXPECTED_BODY, $r->body);
        self::assertSame(['attack-grafana-login'], $r->satisfies->templateIds());
    }

    // --- byte-accurate response shape: valid JSON, no charset suffix -------------------------------

    public function test_body_is_valid_json_and_content_type_carries_no_charset(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('admin')));
        self::assertNotNull($r);
        $decoded = json_decode($r->body, true);
        self::assertNotNull($decoded, 'body must be valid JSON');
        self::assertSame([
            'statusCode' => 401,
            'messageId' => 'password-auth.failed',
            'message' => 'Invalid username or password',
        ], $decoded);
        self::assertSame('application/json', $r->headers['Content-Type'], 'no charset suffix — matches response.JSON()');
    }

    // --- security headers: byte-coherent with a real Grafana 401 -----------------------------------

    public function test_security_headers_are_byte_coherent(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('admin')));
        self::assertNotNull($r);
        self::assertSame('nosniff', $r->headers['X-Content-Type-Options']);
        self::assertSame('deny', $r->headers['X-Frame-Options']);
        self::assertSame('1; mode=block', $r->headers['X-XSS-Protection']);
        self::assertSame('no-store', $r->headers['Cache-Control']);
    }

    // --- SAFETY: never authenticates — no Set-Cookie, no redirect -----------------------------------

    public function test_no_set_cookie_and_no_redirect(): void
    {
        $emu = $this->isolated();
        foreach (['admin', 'alice', 'root'] as $user) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertArrayNotHasKey('Set-Cookie', $r->headers, $user);
            self::assertNotSame(302, $r->status, $user);
            self::assertNotSame(307, $r->status, $user);
            self::assertArrayNotHasKey('Location', $r->headers, $user);
            self::assertArrayNotHasKey('WWW-Authenticate', $r->headers, $user);
        }
    }

    // --- SAFETY: zero-reflection — the submitted user is never reflected, whatever it is -----------

    public function test_submitted_user_is_never_reflected(): void
    {
        $emu = $this->isolated();
        foreach (['admin', 'alice', '900000', 'admin"', "admin' OR '1'='1", '<script>alert(1)</script>'] as $user) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertSame(self::EXPECTED_BODY, $r->body, "response must be fully static: {$user}");
            self::assertStringNotContainsString($user, $r->body, "user must never be reflected: {$user}");
        }
    }

    // --- SAFETY: the paradigm XSS payload never reflects --------------------------------------------

    public function test_xss_payload_user_never_reflected(): void
    {
        $emu = $this->isolated();
        $xss = '<script>alert(1)</script>';
        $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($xss)));
        self::assertNotNull($r);
        self::assertSame(self::EXPECTED_BODY, $r->body);
        self::assertStringNotContainsString($xss, $r->body);
        self::assertStringNotContainsString('<script>', $r->body);
    }

    // --- SAFETY: zero-execution — the password is never read at all --------------------------------

    public function test_password_is_never_read_zero_execution(): void
    {
        $emu = $this->isolated();
        $post = function (string $pass) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('admin', $pass)));
        };
        $a = $post('hunter2');
        $b = $post("admin' OR '1'='1");
        $c = $post('../../etc/passwd');
        $d = $post('phar://a/evil.phar/x');
        self::assertNotNull($a);
        self::assertSame($a->body, $b->body, 'an SQLi password must not change the response');
        self::assertSame($a->body, $c->body, 'a traversal password must not change the response');
        self::assertSame($a->body, $d->body, 'a phar password must not change the response (no egress)');
    }

    // --- priority fix: an injection-laced username must still reach THIS oracle, not a generic body --

    public function test_sqli_ssti_laced_user_still_reaches_the_oracle_not_a_generic_attack_body(): void
    {
        // An injection-laced credential at /grafana/login used to be able to fall through to a lower
        // (higher-priority-number) generic archetype's body if this rule sorted after it. At priority
        // 38 this rule sorts BEFORE 44-ssti-twig/45-ssti-numeric/46-php-glastopf/50-sqli, so the full
        // (non-isolated) compiled set must still answer with this oracle's own static 401 JSON — a
        // real Grafana login answers ANY bad login, payload or not, the same way.
        foreach (["admin' OR '1'='1' --", '{{7*7}}', '${7*7}'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertSame(['attack-grafana-login'], $r->satisfies->templateIds(), $user);
            self::assertSame(401, $r->status, $user);
            self::assertSame(self::EXPECTED_BODY, $r->body, $user);
        }
    }

    // --- fingerprint safety: scan the RENDERED response, not just the authored directive text --------

    public function test_rendered_response_carries_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();

        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('admin')));
        self::assertNotNull($r);

        $hits = $guard->scan($r->body);
        foreach ($r->headers as $name => $value) {
            $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
        }
        self::assertSame([], $hits, 'rendered response must carry no denied fingerprint token');
    }

    // --- gates: no user field --------------------------------------------------------------------

    public function test_post_missing_user_field_does_not_dispatch(): void
    {
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], json_encode(['password' => 'x']))), 'missing user field');
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')), 'empty body');
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '{}')), 'empty JSON object');
    }

    // --- method gate: GET declines (no route here for POST) -----------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', [], $this->body('admin'))),
                "{$verb} must not dispatch"
            );
        }
    }
}
