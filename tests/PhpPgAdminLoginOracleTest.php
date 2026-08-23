<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware phpPgAdmin redirect.php credential emulator (attack rule 99, WP-Phase-2b). A
 * brute/cred-stuffing POST is answered with the authentic re-rendered login page — 200 text/html,
 * never a redirect, never an authenticated session. Pins the load-bearing safety invariants:
 * zero-reflection (the submitted username never surfaces in either branch), zero-execution (the
 * submitted password is never read beyond the fixed-field-name presence gate), never-authenticate
 * (no success path anywhere), and POST-gated (any other verb misses — no route here at all).
 *
 * PRIORITY 43: below the broad `in: request` archetypes 44-ssti-twig/45-ssti-numeric/46-php-glastopf/
 * 50-sqli (no path constraint at all), so an injection-laced `loginUsername=` value at /redirect.php
 * still reaches THIS oracle instead of one of those generic bodies — the same fix 97-wp-login.yaml
 * (39) and 98-cpsrvd-login.yaml (42) already apply. Being path-anchored to redirect.php, this only
 * affects /redirect.php POSTs; those archetypes are untouched on every other path.
 */
final class PhpPgAdminLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/redirect.php';
    private const ID = 'attack-phppgadmin-login';
    private const PWFIELD = 'loginPassword_43535f929f0cc24fff91705ab9522864';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** The compiled phpPgAdmin rule alone, so an adversarial credential can't trip an earlier broad rule. */
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
        return 'loginServer=' . rawurlencode(':5432:allow')
            . '&loginUsername=' . rawurlencode($user)
            . '&' . self::PWFIELD . '=' . rawurlencode($pass);
    }

    // --- compile / ownership ------------------------------------------------------------------------

    public function test_rule_compiled_unique_and_owns_redirect_php(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains(self::ID, $ids);
        self::assertSame(1, array_count_values($ids)[self::ID], 'rule id must be unique');

        self::assertTrue($this->emulator()->ownsPath('/redirect.php'));
    }

    // --- branch A: reserved superuser/admin names → disallowed (also the base/default) ---------------

    public function test_reserved_username_returns_disallowed_for_security_reasons(): void
    {
        foreach (['postgres', 'PostgreS', 'pgsql', 'PGSQL', 'root', 'Root', 'administrator', 'ADMINISTRATOR'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertSame(200, $r->status, $user);
            self::assertSame('text/html; charset=utf-8', $r->headers['Content-Type'], $user);
            self::assertStringContainsString('Login disallowed for security reasons.', $r->body, $user);
            self::assertStringContainsString('7.13.0', $r->body, $user);
            self::assertSame(['attack-phppgadmin-login'], $r->satisfies->templateIds(), $user);
        }
    }

    // --- branch B: any other username → generic Login failed -----------------------------------------

    public function test_non_reserved_username_returns_login_failed(): void
    {
        foreach (['alice', 'admin', 'dbadmin', 'postgresql', 'root2'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertSame(200, $r->status, $user);
            self::assertStringContainsString('Login failed', $r->body, $user);
            self::assertStringNotContainsString('Login disallowed for security reasons.', $r->body, $user);
            self::assertSame(['attack-phppgadmin-login'], $r->satisfies->templateIds(), $user);
        }
    }

    // --- REGRESSION: the two branches' error pages must be byte-identical apart from the message ------

    public function test_both_branches_end_with_the_same_trailing_byte(): void
    {
        // A YAML block-scalar chomping trap: the login-disallowed body (base/default) and the
        // login-failed body (the one branch case) are otherwise identical phpPgAdmin pages, so they
        // must end with the SAME trailing byte(s) — two error pages from the same server differing
        // only by a trailing newline is itself an inconsistency tell.
        $emu = $this->isolated();
        $disallowed = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('postgres')));
        $failed = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('alice')));
        self::assertNotNull($disallowed);
        self::assertNotNull($failed);
        self::assertStringEndsWith("</html>\n", $disallowed->body);
        self::assertStringEndsWith("</html>\n", $failed->body);
        self::assertSame(substr($disallowed->body, -1), substr($failed->body, -1), 'both branch bodies must end with the same trailing byte');
    }

    // --- coherence: topbar + version + password field literal -----------------------------------------

    public function test_topbar_and_password_field_are_byte_coherent(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('alice')));
        self::assertNotNull($r);
        self::assertStringContainsString('<span class="appname">phpPgAdmin</span>', $r->body);
        self::assertStringContainsString('<span class="version">7.13.0</span>', $r->body);
        self::assertStringContainsString('<script type="text/javascript">parent.frames.browser.location.reload();</script>', $r->body);
        self::assertStringContainsString('name="' . self::PWFIELD . '"', $r->body);
    }

    // --- SAFETY: zero-reflection — the submitted username is never reflected in either branch --------

    public function test_submitted_username_is_never_reflected_in_either_branch(): void
    {
        $emu = $this->isolated();
        // 'postgres' takes the disallowed branch; the rest take the login-failed branch — covering
        // the paradigm XSS payload (<script>alert(1)</script>) on BOTH sides of the branch split.
        foreach (['postgres', 'alice', '900000', 'admin"', "admin' OR '1'='1", '<script>alert(1)</script>'] as $user) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertStringNotContainsString($user, $r->body, "username must never be reflected: {$user}");
        }
    }

    // --- SAFETY: the paradigm XSS payload never reflects, whichever branch actually renders -----------

    public function test_xss_payload_username_never_reflected_in_either_branchs_rendered_body(): void
    {
        $emu = $this->isolated();
        $xss = '<script>alert(1)</script>';

        // The payload itself is not a reserved name, so it dispatches to the login-failed branch (the
        // one case) — assert it is absent there.
        $failed = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($xss)));
        self::assertNotNull($failed);
        self::assertStringContainsString('Login failed', $failed->body);
        self::assertStringNotContainsString($xss, $failed->body);

        // The disallowed (base/default) branch is a separate static template with no username slot at
        // all — assert the payload is absent there too, so neither branch could ever reflect it.
        $disallowed = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('postgres')));
        self::assertNotNull($disallowed);
        self::assertStringContainsString('Login disallowed for security reasons.', $disallowed->body);
        self::assertStringNotContainsString($xss, $disallowed->body);
    }

    // --- SAFETY: zero-execution — the password is never read beyond the presence gate -----------------

    public function test_password_is_never_read_zero_execution(): void
    {
        // Same username, wildly different passwords (including injection strings) => byte-identical
        // response. Isolated so a traversal/SQLi payload in the password can't trip another rule.
        $emu = $this->isolated();
        $post = function (string $pass) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body('alice', $pass)));
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

    // --- SAFETY: never authenticates — no redirect, no authenticated cookie --------------------------

    public function test_no_redirect_and_no_authenticated_session_in_either_branch(): void
    {
        $emu = $this->isolated();
        foreach (['postgres', 'alice'] as $user) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertNotSame(302, $r->status, $user);
            self::assertNotSame(307, $r->status, $user);
            self::assertArrayNotHasKey('Location', $r->headers, $user);
            self::assertArrayNotHasKey('WWW-Authenticate', $r->headers, $user);
            // The inert pre-auth PPA_ID cookie is fine — a real phpPgAdmin also sets it before login
            // succeeds; it grants nothing on its own.
            self::assertStringStartsWith('PPA_ID=', $r->headers['Set-Cookie'], $user);
        }
    }

    // --- priority fix: an injection-laced username must still reach THIS oracle, not a generic body --

    public function test_sqli_ssti_laced_username_still_reaches_the_oracle_not_a_generic_attack_body(): void
    {
        // An injection-laced credential at /redirect.php used to be able to fall through to a lower
        // (higher-priority-number) generic archetype's body if this rule sorted after it. At priority
        // 43 this rule sorts BEFORE 44-ssti-twig/45-ssti-numeric/46-php-glastopf/50-sqli, so the full
        // (non-isolated) compiled set must still answer with this oracle's own re-rendered login page —
        // a real phpPgAdmin login form answers ANY bad login, payload or not, the same way.
        foreach (["admin' OR '1'='1' --", '{{7*7}}', '${7*7}'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);
            self::assertSame(['attack-phppgadmin-login'], $r->satisfies->templateIds(), $user);
            self::assertSame(200, $r->status, $user);
            self::assertStringContainsString('Login failed', $r->body, $user);
        }
    }

    // --- fingerprint safety: scan the RENDERED response, not just the authored directive text --------

    public function test_rendered_response_with_expanded_cookie_token_carries_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();

        foreach (['postgres', 'alice'] as $user) {
            $r = $this->emulator()->emulate(new RequestContext('POST', self::PATH, '', [], $this->body($user)));
            self::assertNotNull($r, $user);

            $hits = $guard->scan($r->body);
            foreach ($r->headers as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            self::assertSame([], $hits, 'rendered response (incl. expanded PPA_ID cookie) must carry no denied fingerprint token');
        }
    }

    // --- gates: no loginServer / no dynamic password field / no username -----------------------------

    public function test_post_missing_a_required_field_does_not_dispatch(): void
    {
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], 'loginUsername=postgres&' . self::PWFIELD . '=x')), 'missing loginServer');
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], 'loginServer=' . rawurlencode(':5432:allow') . '&loginUsername=postgres')), 'missing dynamic password field');
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], 'loginServer=' . rawurlencode(':5432:allow') . '&' . self::PWFIELD . '=x')), 'missing loginUsername');
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')), 'empty body');
    }

    // --- method gate: GET declines (no route here at all) ---------------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', [], $this->body('postgres'))),
                "{$verb} must not dispatch"
            );
        }
    }

    // --- position-blind port degradation ---------------------------------------------------------------

    public function test_position_blind_port_serves_the_default_disallowed_base(): void
    {
        // On the position-blind port (renderRule with $r === null) no branch case can be evaluated, so
        // the base/default response serves — still safe degradation, no crash, no reflection, clean scan.
        $port = $this->emulator()->renderRule($this->isolatedRule(), [1 => 'zzcapturedzz'], 0, null);
        self::assertNotNull($port);
        self::assertSame(200, $port->status);
        self::assertStringContainsString('Login disallowed for security reasons.', $port->body);
        self::assertStringNotContainsString('zzcapturedzz', $port->body, 'the captured username must not be reflected on the port');
        self::assertSame([], FingerprintGuard::fromPackage()->scan($port->body));
    }
}
