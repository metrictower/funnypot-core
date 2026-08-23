<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware Kibana /internal/security/login credential emulator (attack rule 101,
 * WP-Phase-2b), coherent with route 372's app-shell bundle (Kibana 7.17.18). The real endpoint's
 * xsrf interceptor runs BEFORE any body parsing, so this rule gates on path + method only and never
 * reads the request body: `behavior: branch` picks the response purely off the `kbn-xsrf` HEADER's
 * presence — absent/empty -> 400 "must contain a kbn-xsrf header"; present -> 401 security_exception.
 * Pins the load-bearing safety invariants: zero-reflection (a FIXED persona username `admin` in the
 * 401 body — the submitted username never surfaces, unlike real Kibana's double-reflection),
 * zero-execution (no body field is ever read), never-authenticate (no Set-Cookie in either branch),
 * and POST-gated (any other verb misses — no route here at all).
 *
 * PRIORITY 37: below the broad `in: request` archetypes 44-ssti-twig/45-ssti-numeric/46-php-glastopf/
 * 50-sqli (no path constraint at all), so an injection-laced `username` value at
 * /internal/security/login still reaches THIS oracle instead of one of those generic bodies — the
 * same fix 97-wp-login.yaml (39), 98-cpsrvd-login.yaml (42), 99-phppgadmin-login.yaml (43), and
 * 100-grafana-login.yaml (38) already apply for the same class of collision.
 */
final class KibanaLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/internal/security/login';
    private const ID = 'attack-kibana-login';
    private const BODY_400 = '{"statusCode":400,"error":"Bad Request","message":"Request must contain a kbn-xsrf header."}';
    private const BODY_401 = '{"statusCode":401,"error":"Unauthorized","message":"[security_exception: [security_exception] Reason: unable to authenticate user [admin] for REST request [/_security/_authenticate]]: unable to authenticate user [admin] for REST request [/_security/_authenticate]"}';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** The compiled Kibana rule alone, so an adversarial credential can't trip an earlier broad rule. */
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

    private function loginBody(string $user, string $pass = 'x'): string
    {
        return json_encode(['providerType' => 'basic', 'params' => ['username' => $user, 'password' => $pass]]);
    }

    // --- compile / ownership ------------------------------------------------------------------------

    public function test_rule_compiled_unique_and_owns_login_path(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains(self::ID, $ids);
        self::assertSame(1, array_count_values($ids)[self::ID], 'rule id must be unique');

        self::assertTrue($this->emulator()->ownsPath(self::PATH));
    }

    // --- branch A: kbn-xsrf header ABSENT -> 400 --------------------------------------------------

    public function test_missing_kbn_xsrf_header_returns_400(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->loginBody('root')));
        self::assertNotNull($r);
        self::assertSame(400, $r->status);
        self::assertSame('application/json; charset=utf-8', $r->headers['Content-Type']);
        self::assertSame(self::BODY_400, $r->body);
        self::assertStringContainsString('kbn-xsrf', $r->body);
        self::assertSame(['attack-kibana-login'], $r->satisfies->templateIds());
    }

    /** A present-but-empty header value must gate the same as an absent header. */
    public function test_empty_kbn_xsrf_header_value_also_returns_400(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => ''], $this->loginBody('root')));
        self::assertNotNull($r);
        self::assertSame(400, $r->status);
        self::assertSame(self::BODY_400, $r->body);
    }

    // --- branch B (base/default): kbn-xsrf header PRESENT -> 401 ------------------------------------

    public function test_present_kbn_xsrf_header_returns_401_with_fixed_admin_username(): void
    {
        $r = $this->emulator()->emulate(new RequestContext(
            'POST',
            self::PATH,
            '',
            ['kbn-xsrf' => 'true'],
            $this->loginBody('root', 'x')
        ));
        self::assertNotNull($r);
        self::assertSame(401, $r->status);
        self::assertSame('application/json; charset=utf-8', $r->headers['Content-Type']);
        self::assertSame(self::BODY_401, $r->body);
        self::assertStringContainsString('security_exception', $r->body);
        self::assertStringContainsString('[admin]', $r->body);
        self::assertStringNotContainsString('root', $r->body, 'the submitted username must never be reflected');
        self::assertSame(['attack-kibana-login'], $r->satisfies->templateIds());
    }

    // --- byte-accurate response shape: valid JSON in both branches ---------------------------------

    public function test_both_branches_are_valid_json(): void
    {
        $absent = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->loginBody('root')));
        $present = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($absent);
        self::assertNotNull($present);

        $decodedAbsent = json_decode($absent->body, true);
        self::assertNotNull($decodedAbsent, 'the 400 body must be valid JSON');
        self::assertSame(['statusCode' => 400, 'error' => 'Bad Request', 'message' => 'Request must contain a kbn-xsrf header.'], $decodedAbsent);

        $decodedPresent = json_decode($present->body, true);
        self::assertNotNull($decodedPresent, 'the 401 body must be valid JSON');
        self::assertSame(401, $decodedPresent['statusCode']);
        self::assertSame('Unauthorized', $decodedPresent['error']);
    }

    // --- REGRESSION: both branch bodies must end consistently (no chomping mismatch) ---------------

    public function test_both_branches_end_with_the_same_trailing_byte(): void
    {
        // Both bodies are single-line quoted JSON scalars (not YAML block literals), so neither is
        // subject to the block-scalar chomping trap a prior oracle (99-phppgadmin-login.yaml) hit —
        // pinned here as a regression guard: neither body carries a trailing newline, and both agree.
        $emu = $this->isolated();
        $absent = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->loginBody('root')));
        $present = $emu->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($absent);
        self::assertNotNull($present);
        self::assertStringEndsWith('"}', $absent->body);
        self::assertStringEndsWith('"}', $present->body);
        self::assertFalse(strpos($absent->body, "\n") !== false, '400 body must carry no embedded newline');
        self::assertFalse(strpos($present->body, "\n") !== false, '401 body must carry no embedded newline');
    }

    // --- realism headers: present only on the 401 (kbn-xsrf-present) branch -------------------------

    public function test_realism_headers_present_only_on_401_branch(): void
    {
        $present = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($present);
        self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $present->headers['kbn-license-sig'], 'kbn-license-sig must be a fixed 64-hex token');
        self::assertDoesNotMatchRegularExpression('/^[0-9a-f]{12}$/', $present->headers['kbn-name'], 'kbn-name must never look like a container id');
        self::assertDoesNotMatchRegularExpression('/^[0-9a-f]{64}$/', $present->headers['kbn-name'], 'kbn-name must never look like a container id');
        self::assertSame('nosniff', $present->headers['x-content-type-options']);
        self::assertSame('no-referrer-when-downgrade', $present->headers['referrer-policy']);
        self::assertSame('private, no-cache, no-store, must-revalidate', $present->headers['cache-control']);

        $absent = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->loginBody('root')));
        self::assertNotNull($absent);
        self::assertArrayNotHasKey('kbn-license-sig', $absent->headers);
        self::assertArrayNotHasKey('kbn-name', $absent->headers);
    }

    // --- SAFETY: never authenticates — no Set-Cookie, no redirect, in either branch -----------------

    public function test_no_set_cookie_and_no_redirect_in_either_branch(): void
    {
        $emu = $this->isolated();
        foreach ([[], ['kbn-xsrf' => 'true']] as $headers) {
            foreach (['admin', 'alice', 'root'] as $user) {
                $r = $emu->emulate(new RequestContext('POST', self::PATH, '', $headers, $this->loginBody($user)));
                self::assertNotNull($r, $user);
                self::assertArrayNotHasKey('Set-Cookie', $r->headers, $user);
                self::assertArrayNotHasKey('set-cookie', $r->headers, $user);
                self::assertNotSame(302, $r->status, $user);
                self::assertNotSame(307, $r->status, $user);
                self::assertArrayNotHasKey('Location', $r->headers, $user);
                self::assertArrayNotHasKey('WWW-Authenticate', $r->headers, $user);
            }
        }
    }

    // --- SAFETY: zero-reflection — the submitted username is NEVER reflected, whatever it is --------

    public function test_submitted_username_is_never_reflected(): void
    {
        $emu = $this->isolated();
        foreach (['admin', 'alice', '900000', 'admin"', "admin' OR '1'='1", '<script>alert(1)</script>'] as $user) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody($user)));
            self::assertNotNull($r, $user);
            self::assertSame(self::BODY_401, $r->body, "response must be fully static: {$user}");
            if ($user !== 'admin') {
                self::assertStringNotContainsString($user, $r->body, "user must never be reflected: {$user}");
            }
        }
    }

    // --- SAFETY: the paradigm XSS payload never reflects, in either branch --------------------------

    public function test_xss_payload_username_never_reflected_in_either_branch(): void
    {
        $emu = $this->isolated();
        $xss = '<script>alert(1)</script>';

        $present = $emu->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody($xss)));
        self::assertNotNull($present);
        self::assertSame(self::BODY_401, $present->body);
        self::assertStringNotContainsString($xss, $present->body);
        self::assertStringNotContainsString('<script>', $present->body);

        $absent = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->loginBody($xss)));
        self::assertNotNull($absent);
        self::assertSame(self::BODY_400, $absent->body);
        self::assertStringNotContainsString($xss, $absent->body);
    }

    // --- SAFETY: zero-execution — no body field is ever read, whatever it contains ------------------

    public function test_body_is_never_read_zero_execution(): void
    {
        $emu = $this->isolated();
        $post = function (?string $body) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $body));
        };
        $a = $post($this->loginBody('admin', 'hunter2'));
        $b = $post($this->loginBody('admin', "admin' OR '1'='1"));
        $c = $post('not even json {{{');
        $d = $post('');
        $e = $post(null);
        self::assertNotNull($a);
        self::assertSame($a->body, $b->body, 'an SQLi password must not change the response');
        self::assertSame($a->body, $c->body, 'malformed body must not change the response');
        self::assertSame($a->body, $d->body, 'an empty body must not change the response');
        self::assertSame($a->body, $e->body, 'a null body must not change the response');
    }

    // --- priority fix: an injection-laced username must still reach THIS oracle, not a generic body --

    public function test_sqli_ssti_laced_username_still_reaches_the_oracle_not_a_generic_attack_body(): void
    {
        // An injection-laced credential at /internal/security/login used to be able to fall through
        // to a lower (higher-priority-number) generic archetype's body if this rule sorted after it.
        // At priority 37 this rule sorts BEFORE 44-ssti-twig/45-ssti-numeric/46-php-glastopf/50-sqli,
        // so the full (non-isolated) compiled set must still answer with this oracle's own static 401
        // JSON — a real Kibana login answers ANY bad login, payload or not, the same way.
        foreach (["admin' OR '1'='1' --", '{{7*7}}', '${7*7}', 'admin" UNION SELECT 1--'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext(
                'POST',
                self::PATH,
                '',
                ['kbn-xsrf' => 'true'],
                $this->loginBody($user)
            ));
            self::assertNotNull($r, $user);
            self::assertSame(['attack-kibana-login'], $r->satisfies->templateIds(), $user);
            self::assertSame(401, $r->status, $user);
            self::assertSame(self::BODY_401, $r->body, $user);
        }
    }

    // --- fingerprint safety: scan the RENDERED response (both branches), not just the authored text --

    public function test_rendered_response_carries_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();

        foreach ([[], ['kbn-xsrf' => 'true']] as $headers) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', $headers, $this->loginBody('admin')));
            self::assertNotNull($r);

            $hits = $guard->scan($r->body);
            foreach ($r->headers as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            self::assertSame([], $hits, 'rendered response must carry no denied fingerprint token');
        }
    }

    /** The rendered fingerprint sweep across several persona seeds, so a seed-specific hostname/hex
     *  collision with the denylist can't slip through untested. */
    public function test_rendered_response_carries_no_denied_fingerprint_token_across_seeds(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $rule = $this->isolatedRule();
        $emu = new TemplateAttackEmulator([$rule]);

        foreach ([0, 1, 2, 42, 12345, 999999] as $seed) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('admin')), $seed);
            self::assertNotNull($r, "seed {$seed}");

            $hits = $guard->scan($r->body);
            foreach ($r->headers as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            self::assertSame([], $hits, "rendered response must carry no denied fingerprint token (seed {$seed})");
        }
    }

    // --- method gate: GET declines (no route here at all) -------------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('admin'))),
                "{$verb} must not dispatch"
            );
        }
    }

    // --- position-blind port degradation ---------------------------------------------------------------

    public function test_position_blind_port_serves_the_default_401_base(): void
    {
        // On the position-blind port (renderRule with $r === null) no branch case can be evaluated
        // (the header can't be read without a request), so the base/default 401 response serves —
        // still safe degradation, no crash, no reflection, clean scan.
        $port = $this->emulator()->renderRule($this->isolatedRule(), [], 0, null);
        self::assertNotNull($port);
        self::assertSame(401, $port->status);
        self::assertSame(self::BODY_401, $port->body);
        self::assertSame([], FingerprintGuard::fromPackage()->scan($port->body));
    }
}
