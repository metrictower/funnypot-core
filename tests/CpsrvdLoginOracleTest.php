<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware cpsrvd `/login/` credential emulator (attack rule 98, WP-Phase-2b), shared by
 * BOTH cPanel (route 382) and WHM (route 383) — both panels' login forms POST to the same cpsrvd
 * `/login/` endpoint. Drives the compiled attack rules against a live RequestContext, pinning the
 * zero-reflection and never-authenticate safety invariants and the `login_only=1` branch dispatch.
 *
 * PRIORITY 42: below the broad `in: request` archetypes 44-ssti-twig/45-ssti-numeric/46-php-glastopf/
 * 50-sqli/60-open-redirect/65-xss-reflect (no path constraint at all), so an injection-laced `user=`
 * value at /login/ still reaches THIS oracle instead of one of those generic bodies — the same fix
 * 97-wp-login.yaml already applies at priority 39. Being path-anchored to /login/, this only affects
 * /login/ POSTs; those archetypes are untouched on every other path. 42 sits above 40-cmdi-windows/
 * 41-cmdi-unix and the 20-31 LFI/XXE archetypes, so a shell-metacharacter or path-traversal username
 * can still shadow this rule — the same residual gap wp-login also carries above its own priority 39
 * (its comment explains it was chosen to dodge ONE exact field-name collision, not every archetype).
 *
 * NOTE ON ADVERSARIAL PAYLOADS: a `user=`/`pass=` value crafted to look like a shell-metacharacter or
 * path-traversal probe can still trip an earlier archetype (see the residual gap above). Zero-
 * reflection/zero-execution assertions over such a crafted username therefore run against the rule in
 * ISOLATION (this rule alone), the same isolation pattern WebminSessionLoginTest uses for rule 94.
 */
final class CpsrvdLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const ID = 'attack-cpsrvd-login';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** The compiled cpsrvd rule alone, so an adversarial credential can't trip an earlier broad rule. */
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

    public function test_rule_compiled_and_owns_both_slash_variants_of_login(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains('attack-cpsrvd-login', $ids);

        self::assertTrue($this->emulator()->ownsPath('/login/'));
        self::assertTrue($this->emulator()->ownsPath('/login'));
    }

    // --- login_only=1 branch: the JSON AJAX answer --------------------------------------------------

    public function test_login_only_branch_returns_the_exact_json_oracle(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'));
        self::assertNotNull($r);

        self::assertSame(401, $r->status);
        self::assertSame('text/plain; charset="utf-8"', $r->headers['Content-Type']);
        self::assertSame('{"status":0,"message":"see_login_log"}', $r->body);
        self::assertSame(38, strlen($r->body));
        self::assertArrayNotHasKey('Location', $r->headers);
        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('cpsession=', $r->headers['Set-Cookie']);
        self::assertStringNotContainsString('root', $r->body);
        self::assertSame(['attack-cpsrvd-login'], $r->satisfies->templateIds());
    }

    // --- default branch (no login_only): the HTML login-failed page ---------------------------------

    public function test_default_branch_returns_the_html_invalid_login_page(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/login/', '', [], 'user=root&pass=x'));
        self::assertNotNull($r);

        self::assertSame(401, $r->status);
        self::assertSame('text/html; charset=utf-8', $r->headers['Content-Type']);
        self::assertStringContainsString('The login is invalid.', $r->body);
        self::assertArrayNotHasKey('Location', $r->headers);
        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('cpsession=', $r->headers['Set-Cookie']);
        self::assertSame(['attack-cpsrvd-login'], $r->satisfies->templateIds());
    }

    public function test_a_login_only_value_other_than_1_takes_the_default_html_branch(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=0', [], 'user=root&pass=x'));
        self::assertNotNull($r);
        self::assertStringContainsString('The login is invalid.', $r->body);
    }

    // --- priority fix: an injection-laced username must still reach THIS oracle, not a generic body --

    public function test_sqli_ssti_laced_username_still_reaches_the_oracle_not_a_generic_attack_body(): void
    {
        // Reproduces the exact review repro: `user=admin' OR '1'='1' --` on POST /login/?login_only=1
        // used to fall through to attack-sqli's generic body (priority 50 < the old priority 98). At
        // priority 42 this rule now sorts BEFORE 44-ssti-twig/45-ssti-numeric/46-php-glastopf/50-sqli,
        // so the full (non-isolated) compiled set must still answer with the exact JSON oracle — a
        // real cpsrvd login form answers ANY bad login, payload or not, the same way.
        foreach (["admin' OR '1'='1' --", '{{7*7}}', '${7*7}'] as $user) {
            $payload = 'user=' . rawurlencode($user) . '&pass=x';
            $r = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], $payload));
            self::assertNotNull($r, $user);
            self::assertSame(['attack-cpsrvd-login'], $r->satisfies->templateIds(), $user);
            self::assertSame(401, $r->status, $user);
            self::assertSame('{"status":0,"message":"see_login_log"}', $r->body, $user);
        }
    }

    // --- fingerprint safety: scan the RENDERED response, not just the authored directive text -------

    public function test_rendered_response_with_expanded_cookie_tokens_carries_no_denied_fingerprint_token(): void
    {
        // The CI gate (scripts/ci/check-fingerprint-safety.php) only ever sees the compiled artifact's
        // authored `{{fake.*}}` directive text — never the runtime-expanded hex it renders to. Render
        // the served response here (cp_sid/cp_ob actually expanded into the cpsession cookie) and scan
        // THAT, so a future edit that glues the tokens to their %3a/%2c punctuation differently can't
        // silently produce a denylisted substring without failing a test.
        $guard = FingerprintGuard::fromPackage();

        foreach ([
            ['login_only=1', 'user=root&pass=x'],
            ['', 'user=root&pass=x'],
        ] as [$query, $body]) {
            $r = $this->emulator()->emulate(new RequestContext('POST', '/login/', $query, [], $body));
            self::assertNotNull($r);

            $hits = $guard->scan($r->body);
            foreach ($r->headers as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            self::assertSame([], $hits, 'rendered response (incl. expanded cpsession cookie) must carry no denied fingerprint token');
        }
    }

    // --- coherence: Server/Version match routes 382/383 (one host) ----------------------------------

    public function test_server_and_version_are_coherent_with_the_panel_routes(): void
    {
        $json = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'));
        $html = $this->emulator()->emulate(new RequestContext('POST', '/login/', '', [], 'user=root&pass=x'));
        self::assertNotNull($json);
        self::assertNotNull($html);
        self::assertSame('cpsrvd/11.118.0.13', $json->headers['Server']);
        self::assertSame('cpsrvd/11.118.0.13', $html->headers['Server']);
        self::assertStringContainsString('Version 118.0.13', $html->body);
    }

    // --- SAFETY: zero-reflection — the submitted username is captured only to gate the match --------

    public function test_submitted_username_is_never_reflected_in_either_branch(): void
    {
        $json = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'));
        $html = $this->emulator()->emulate(new RequestContext('POST', '/login/', '', [], 'user=root&pass=x'));
        self::assertNotNull($json);
        self::assertNotNull($html);
        self::assertStringNotContainsString('root', $json->body);
        self::assertStringNotContainsString('root', $html->body);
    }

    public function test_crafted_username_never_surfaces_in_either_branch(): void
    {
        // Isolated: a `<script>`/SQLi-flavored username can trip an earlier broad archetype (44-65)
        // in the full compiled set (the accepted shadow noted above) — irrelevant to what THIS rule
        // does with the capture, which is what this assertion pins.
        $emu = $this->isolated();
        foreach (['<script>alert(1)</script>', "admin' OR '1'='1", '900000'] as $user) {
            $payload = 'user=' . rawurlencode($user) . '&pass=x';

            $json = $emu->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], $payload));
            $html = $emu->emulate(new RequestContext('POST', '/login/', '', [], $payload));
            self::assertNotNull($json, $user);
            self::assertNotNull($html, $user);
            self::assertStringNotContainsString($user, $json->body, $user);
            self::assertStringNotContainsString($user, $html->body, $user);
        }
    }

    // --- SAFETY: never authenticates — no 302/307, no authenticated cookie --------------------------

    public function test_no_redirect_and_no_authenticated_cookie_in_either_branch(): void
    {
        $json = $this->emulator()->emulate(new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'));
        $html = $this->emulator()->emulate(new RequestContext('POST', '/login/', '', [], 'user=root&pass=x'));
        self::assertNotNull($json);
        self::assertNotNull($html);

        foreach ([$json, $html] as $r) {
            self::assertNotSame(302, $r->status);
            self::assertNotSame(307, $r->status);
            self::assertArrayNotHasKey('Location', $r->headers);
            self::assertArrayNotHasKey('WWW-Authenticate', $r->headers);
            // The inert pre-auth cpsession cookie is fine (leading %3a = empty user slot); it grants
            // nothing. No authenticated-session token is ever set.
            self::assertStringContainsString('cpsession=%3a', $r->headers['Set-Cookie']);
        }
    }

    // --- POST-gated: a GET must decline (no route here at all) --------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        // Isolated: this rule alone, so a strict assertNull is unambiguous — no other compiled rule
        // can supply a response for the isolated emulator to return instead.
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, '/login/', '', [], 'user=root&pass=x')),
                "{$verb} must not dispatch"
            );
            self::assertNull(
                $emu->emulate(new RequestContext($verb, '/login/', 'login_only=1', [], 'user=root&pass=x')),
                "{$verb} with login_only=1 must not dispatch"
            );
        }
    }
}
