<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
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
 *
 * owns_path IS LOAD-BEARING here (unlike a rule with no real-store collision): the REAL compiled
 * corpus resources/compiled/nuclei-index.full.php — what PhpArrayStore::fromPackage() loads in prod —
 * has a live exact-store bundle keyed EXACTLY `POST /login/` (nuclei template `szhe-default-login`):
 * a fake LOGIN-SUCCESS, status 302 redirecting to `/` with a `Set-Cookie: session` header-watch —
 * a DANGEROUS fake session, more so than Kibana's fake sid= (this one also carries a plausible
 * redirect-to-home). Without owns_path, classify() would resolve a POST here to that dangerous corpus
 * bundle instead of this oracle; see test_classify_overrides_the_live_szhe_default_login_bundle and
 * test_served_response_is_the_oracle_never_the_szhe_login_success_bundle below, which drive a full
 * Honeypot over the REAL corpus (not the compiled attack rules alone) to pin the override.
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

    /**
     * A full Honeypot over the REAL compiled corpus (nuclei-index.full.php — what
     * PhpArrayStore::fromPackage() loads in prod), not the small test fixture. This is the only way
     * to reproduce the live `POST /login/` = szhe-default-login collision owns_path overrides; mirrors
     * KibanaLoginOracleTest::fullEngine(), with mode='respond' (+ a permissive gate) when the test
     * also needs the actual served bytes, not just the verdict.
     */
    private function fullEngine(bool $respondMode = false, string $ceiling = 'high'): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            $respondMode ? 'respond' : 'detect',
            $respondMode ? static function (RequestContext $r): bool { return true; } : null,
            'matched-only', null, 'coherent', Style::MINIMAL,
            $ceiling, 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
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

    // --- REGRESSION: owns_path overrides a LIVE dangerous corpus bundle at this exact path ----------

    /**
     * The real compiled corpus (nuclei-index.full.php) has a bundle keyed EXACTLY `POST /login/` —
     * nuclei template `szhe-default-login`, a fake LOGIN-SUCCESS (status 302, redirect to `/`,
     * `Set-Cookie: session`). Without owns_path, classify() would resolve this request to a ROUTE
     * handle onto that bundle (Verdict::SCANNER_PROBE), not this oracle. This pins that classify()
     * instead returns the ATTACK_CLASS verdict with THIS rule's handle, so a future owns_path removal
     * or corpus/index rebuild that drops the override can't silently regress into serving a fake
     * authenticated session.
     */
    public function test_classify_overrides_the_live_szhe_default_login_bundle(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(
            FakeHandle::KIND_ATTACK,
            $verdict->fakeHandle->kind,
            'must be the attack-tier handle, not a route handle onto the szhe-default-login bundle'
        );
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    /**
     * The actual served bytes (via the full respond() facade over the REAL corpus) must be this
     * oracle's response — never the szhe-default-login bundle's 302 redirect-to-home with its
     * `Set-Cookie: session` fake login-success.
     */
    public function test_served_response_is_the_oracle_never_the_szhe_login_success_bundle(): void
    {
        $engine = $this->fullEngine(true);

        $r = $engine->respond(new RequestContext('POST', '/login/', 'login_only=1', [], 'user=root&pass=x'));
        self::assertNotNull($r);
        self::assertSame(401, $r->status, 'must not be the szhe bundle\'s 302 redirect');
        self::assertSame('{"status":0,"message":"see_login_log"}', $r->body);
        self::assertStringNotContainsString(
            'You should be redirected automatically to target URL',
            $r->body,
            'must not be the szhe bundle\'s redirect body'
        );
        self::assertArrayNotHasKey('Location', $r->headers);
        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertStringStartsWith(
            'cpsession=',
            $r->headers['Set-Cookie'],
            'must be the cpsrvd pre-auth cookie, not the szhe bundle\'s bare session= cookie'
        );
    }

    // --- REGRESSION: adversarial canonical-variant requests must still win, never fall through -------

    /**
     * WP-Phase-2b safety fix: PathNormalizer::ownershipKey() lower-cases the path and strips a
     * trailing slash, so ownsPath() returns true for a case/trailing-slash/method/body variant of the
     * owned path — but the oracle's OWN match used to be stricter (method `ci: false`, path
     * `ci: false`, and a body condition that REQUIRED a `user=` field to be present). Such a variant
     * request made ownsPath() true (entering the override) while matchRule() declined, so classify()
     * fell through to resolveEntry(), which re-resolved the SAME variant onto the live
     * `szhe-default-login` bundle (302 redirect to `/`, `Set-Cookie: session`) — a fake LOGIN-SUCCESS.
     * The oracle's match is now as permissive as ownsPath's canonical form (and its `user=` capture is
     * optional), so every variant below must win instead: ATTACK_CLASS + KIND_ATTACK, and the served
     * bytes must be this oracle's own response, never the bundle's 302/`Set-Cookie: session`.
     *
     * @dataProvider adversarialVariantProvider
     */
    public function test_adversarial_variants_win_never_the_szhe_login_success_bundle(
        string $method,
        string $path,
        string $body
    ): void {
        $verdict = $this->fullEngine()->classify(
            new RequestContext($method, $path, '', [], $body),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, "{$method} {$path} [{$body}]");
        self::assertNotNull($verdict->fakeHandle, "{$method} {$path} [{$body}]");
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind, "{$method} {$path} [{$body}]: must be the attack-tier handle, not a route handle onto szhe-default-login");
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId, "{$method} {$path} [{$body}]");

        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext($method, $path, '', [], $body));
        self::assertNotNull($r, "{$method} {$path} [{$body}]");
        self::assertSame(401, $r->status, "{$method} {$path} [{$body}]: must not be the bundle's 302 redirect");
        self::assertArrayNotHasKey('Location', $r->headers, "{$method} {$path} [{$body}]");
        self::assertStringNotContainsString(
            'You should be redirected automatically to target URL',
            $r->body,
            "{$method} {$path} [{$body}]: must not be the szhe bundle's redirect body"
        );
        self::assertStringStartsWith('cpsession=', $r->headers['Set-Cookie'], "{$method} {$path} [{$body}]");
    }

    /** @return array<string,array{0:string,1:string,2:string}> */
    public function adversarialVariantProvider(): array
    {
        return [
            'trailing slash' => ['POST', '/login/', 'user=root&pass=x'],
            // MULTI-trailing-slash (second adversarial-review finding): ownershipKey() rtrim()s ALL
            // trailing slashes, not just one, so ownsPath() is equally true for '//' and '///'; the
            // path regex (`/*$`, not `/?$`) must tolerate any count.
            'double trailing slash' => ['POST', '/login//', 'user=root&pass=x'],
            'triple trailing slash' => ['POST', '/login///', 'user=root&pass=x'],
            // 100-grafana-login.yaml no longer carries a bare `login` alias (WP-Phase-2b removed it:
            // it shadowed this rule's owned `/login/` on the no-trailing-slash form), so a mixed-case
            // path is now unambiguous — it can only match THIS rule.
            'mixed-case path' => ['POST', '/Login/', 'user=root&pass=x'],
            'lowercase method' => ['post', '/login/', 'user=root&pass=x'],
            'body missing user field' => ['POST', '/login/', 'pass=x'],
            'empty body' => ['POST', '/login/', ''],
        ];
    }

    /**
     * A query string appended to a multi-slash path must not change the match: `in: path`/`in:
     * method` read $r->path/$r->method only, never $r->query (PathNormalizer::ownershipKey() is
     * likewise query-blind — ownsPath() is called with $r->path alone). Reproduces the exact
     * second-review repro `POST /login//?a=b`.
     */
    public function test_query_appended_to_a_multi_slash_path_still_wins(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/login//', 'a=b', [], 'user=root&pass=x'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);

        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext('POST', '/login//', 'a=b', [], 'user=root&pass=x'));
        self::assertNotNull($r);
        self::assertSame(401, $r->status, "must not be the szhe bundle's 302 redirect");
        self::assertArrayNotHasKey('Location', $r->headers);
        self::assertStringStartsWith('cpsession=', $r->headers['Set-Cookie']);
    }

    // --- REGRESSION: a HEAD variant the oracle can never match (POST-gated) must still never --------
    // --- expose whatever entry resolveEntry's HEAD->GET degradation falls back onto ------------------

    /**
     * Second adversarial-review finding: a HEAD request can never satisfy this oracle's method
     * condition (`^POST$`), so ownsPath('/login//') is true while matchRule() legitimately declines.
     * Unlike wp-login.php (which has a real `HEAD /wp-login.php` auth-success bundle), the real
     * compiled corpus has no `HEAD /login` entry — resolveEntry()'s HEAD-falls-back-to-GET
     * degradation lands on the persona-capped `GET /login` entry instead (~40 assorted login-panel
     * pages, none an auth-success bundle). Either outcome is safe here: Honeypot::classify()'s
     * hasAuthSuccessWitness guard would degrade to CLEAN if that fallthrough entry DID carry a
     * witness; since it doesn't, the request instead falls through to that benign route bundle. This
     * pins that whichever it is, the served bytes are never the szhe-default-login success shape, at
     * BOTH the default (high) and critical severity ceiling.
     *
     * @dataProvider headAndMultiSlashVariantProvider
     */
    public function test_head_and_multi_slash_variants_never_expose_the_szhe_login_success_bundle(
        string $method,
        string $path,
        string $query
    ): void {
        foreach (['high', 'critical'] as $ceiling) {
            $engine = $this->fullEngine(true, $ceiling);
            $r = $engine->respond(new RequestContext($method, $path, $query, [], 'user=root&pass=x'));
            $label = "{$method} {$path}?{$query} @ceiling={$ceiling}";

            if ($r === null) {
                self::assertNull($r, $label); // CLEAN (guard fired) or gate-declined — the safe outcome.
                continue;
            }

            self::assertNotSame(302, $r->status, $label);
            self::assertArrayNotHasKey('Location', $r->headers, $label);
            self::assertStringNotContainsString(
                'You should be redirected automatically to target URL',
                $r->body,
                $label
            );
            $headerBlock = implode(' ', $r->headers);
            self::assertStringNotContainsString('sid=', $headerBlock, $label);
            self::assertStringNotContainsString('logged_in', strtolower($headerBlock), $label);
        }
    }

    /** @return array<string,array{0:string,1:string,2:string}> */
    public function headAndMultiSlashVariantProvider(): array
    {
        return [
            'HEAD double trailing slash' => ['HEAD', '/login//', ''],
            'HEAD triple trailing slash' => ['HEAD', '/login///', ''],
        ];
    }

    // --- REGRESSION: alias removal — cpsrvd now cleanly owns bare /login, grafana no longer swallows -

    /**
     * WP-Phase-2b (second adversarial review): 100-grafana-login.yaml used to carry a bare `login`
     * alias in its match regex that shadowed THIS rule's owned `/login/` on the no-trailing-slash
     * form (grafana sorted first, priority 38 < 42) — a pre-existing oracle-vs-oracle overlap. That
     * alias is now removed, so a bare `POST /login` (no trailing slash at all) must be answered by
     * THIS oracle (cpsrvd's 401 "The login is invalid."), never grafana's `password-auth.failed`
     * JSON — proving cpsrvd now cleanly owns the whole `/login`(/) surface.
     */
    public function test_bare_login_no_trailing_slash_is_owned_by_cpsrvd_not_grafana(): void
    {
        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext('POST', '/login', '', [], 'user=root&pass=x'));
        self::assertNotNull($r);
        self::assertSame(401, $r->status);
        self::assertStringContainsString('The login is invalid.', $r->body);
        self::assertStringNotContainsString('password-auth.failed', $r->body, 'must not be grafana\'s oracle');
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
