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
 * The request-aware Grafana /grafana/login credential emulator (attack rule 100, WP-Phase-2b),
 * coherent with route 379's login shell (Grafana 10.4.2, appSubUrl /grafana). A bad-credential POST
 * is answered with the authentic static 401 `password-auth.failed` JSON body — Grafana's simplest
 * failure shape, no branching. Pins the load-bearing safety invariants: zero-reflection (the
 * submitted `user` field never surfaces in the response — the body is fully static), zero-execution
 * (the password is never read at all), never-authenticate (no Set-Cookie — Grafana's session cookie
 * is success-only), and POST-gated (any other verb misses — no route here for POST).
 *
 * owns_path IS LOAD-BEARING here (unlike a rule with no real-store collision): the REAL compiled
 * corpus resources/compiled/nuclei-index.full.php — what PhpArrayStore::fromPackage() loads in prod —
 * merges in funnypot's own routes, and has a live exact-store bundle keyed `GET /grafana/login`
 * (pid `route-grafana-login`, route 379's static HTML login shell, body-watch token `Grafana`).
 * resolveEntry()'s POST-falls-back-to-GET degradation (no `POST /grafana/login` key exists) means a
 * POST here resolves that GET entry first. Without owns_path, classify() would resolve this POST to
 * a ROUTE handle onto route 379's page (Verdict::SCANNER_PROBE), not this oracle; see
 * test_classify_overrides_the_live_route_grafana_login_get_page and
 * test_served_response_is_the_oracle_never_route_379s_html_login_page below, which drive a full
 * Honeypot over the REAL corpus (not the compiled attack rules alone) to pin the override.
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

    /**
     * A full Honeypot over the REAL compiled corpus (nuclei-index.full.php — what
     * PhpArrayStore::fromPackage() loads in prod), not the small test fixture. This is the only way
     * to reproduce the live `GET /grafana/login` = route-grafana-login collision (reached on a POST
     * via resolveEntry's POST->GET fallback) owns_path overrides; mirrors
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

    // --- REGRESSION: owns_path overrides a LIVE corpus route bundle reached via the GET fallback ----

    /**
     * The real compiled corpus (nuclei-index.full.php) has a bundle keyed `GET /grafana/login` (pid
     * `route-grafana-login`, route 379's static HTML login page). resolveEntry() falls a POST with no
     * `POST /grafana/login` key back onto that GET entry. Without owns_path, classify() would resolve
     * this POST to a ROUTE handle onto route 379 (Verdict::SCANNER_PROBE), not this oracle. This pins
     * that classify() instead returns the ATTACK_CLASS verdict with THIS rule's handle, so a future
     * owns_path removal or corpus/index rebuild that drops the override can't silently regress into
     * serving the static login page for a POST credential attempt.
     */
    public function test_classify_overrides_the_live_route_grafana_login_get_page(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', self::PATH, '', [], $this->body('admin')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(
            FakeHandle::KIND_ATTACK,
            $verdict->fakeHandle->kind,
            "must be the attack-tier handle, not a route handle onto route 379's GET login page"
        );
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    /**
     * The actual served bytes (via the full respond() facade over the REAL corpus) must be this
     * oracle's static 401 `password-auth.failed` JSON — never route 379's HTML login page (its
     * `Grafana` body-watch token, plain-text/html shape).
     */
    public function test_served_response_is_the_oracle_never_route_379s_html_login_page(): void
    {
        $engine = $this->fullEngine(true);

        $r = $engine->respond(new RequestContext('POST', self::PATH, '', [], $this->body('admin')));
        self::assertNotNull($r);
        self::assertSame(401, $r->status, "must not be route 379's 200 HTML page");
        self::assertSame(self::EXPECTED_BODY, $r->body);
        self::assertSame('application/json', $r->headers['Content-Type'], "must not be route 379's HTML content type");
    }

    // --- REGRESSION: adversarial canonical-variant requests must still win --------------------------

    /**
     * WP-Phase-2b safety fix, applied to Grafana for robustness/consistency with the other three
     * login oracles: PathNormalizer::ownershipKey() lower-cases the path and strips a trailing slash,
     * so ownsPath() returns true for a case/trailing-slash/method variant of the owned path. The
     * oracle's match is now as permissive as ownsPath's canonical form, so every variant below must
     * still win: ATTACK_CLASS + KIND_ATTACK, and the served bytes must be this oracle's own static
     * 401 JSON — never route 379's GET login shell (this fallthrough was always benign, unlike the
     * other three oracles, but the invariant is kept identical across all four for consistency).
     *
     * @dataProvider adversarialVariantProvider
     */
    public function test_adversarial_variants_win_never_route_379s_html_login_page(
        string $method,
        string $path
    ): void {
        $verdict = $this->fullEngine()->classify(
            new RequestContext($method, $path, '', [], $this->body('admin')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, "{$method} {$path}");
        self::assertNotNull($verdict->fakeHandle, "{$method} {$path}");
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind, "{$method} {$path}: must be the attack-tier handle, not route 379's GET login page");
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId, "{$method} {$path}");

        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext($method, $path, '', [], $this->body('admin')));
        self::assertNotNull($r, "{$method} {$path}");
        self::assertSame(401, $r->status, "{$method} {$path}: must not be route 379's 200 HTML page");
        self::assertSame(self::EXPECTED_BODY, $r->body, "{$method} {$path}");
        self::assertSame('application/json', $r->headers['Content-Type'], "{$method} {$path}: must not be route 379's HTML content type");
    }

    /** @return array<string,array{0:string,1:string}> */
    public function adversarialVariantProvider(): array
    {
        return [
            'trailing slash' => ['POST', self::PATH . '/'],
            // MULTI-trailing-slash (second adversarial-review finding): ownershipKey() rtrim()s ALL
            // trailing slashes, not just one, so ownsPath() is equally true for '//' and '///'; the
            // path regex (`/*$`, not `/?$`) must tolerate any count.
            'double trailing slash' => ['POST', self::PATH . '//'],
            'triple trailing slash' => ['POST', self::PATH . '///'],
            'mixed-case path' => ['POST', '/Grafana/Login'],
            'lowercase method' => ['post', self::PATH],
        ];
    }

    // --- REGRESSION: the bare `login` alias is REMOVED — it used to shadow cpsrvd's owned /login/ ----

    /**
     * WP-Phase-2b (second adversarial review): this rule's match regex used to also accept a bare
     * `login` alias (`(?:^|/)(?:grafana/login/?|login)$`) — any single last path segment named
     * `login`, `grafana/` prefix or not. That alias shadowed 98-cpsrvd-login.yaml's owned `/login/`
     * on the no-trailing-slash form (this rule sorted first in the priority scan, 38 < 42): a bare
     * `POST /login` was answered by THIS oracle instead of cpsrvd's — a pre-existing, harmless
     * oracle-vs-oracle overlap, but one that no longer needs to exist once this rule is narrowed to
     * its own real path with slash tolerance. The alias is now gone: this rule must no longer match a
     * bare `/login` at all (isolated, so cpsrvd's own rule can't supply the response instead).
     */
    public function test_bare_login_alias_is_removed(): void
    {
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', '/login', '', [], $this->body('admin'))));
        self::assertNull($emu->emulate(new RequestContext('POST', '/login/', '', [], $this->body('admin'))));
        self::assertNull($emu->emulate(new RequestContext('POST', '/some/path/login', '', [], $this->body('admin'))));
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

    // --- WP-Phase-2b fix: a POST with no `user` field still dispatches (owns_path is permissive) -----

    /**
     * The `user` capture is OPTIONAL (WP-Phase-2b fix): a body missing the `user` field, an empty
     * body, or an empty JSON object must still dispatch this oracle's static 401, exactly like a body
     * that does carry `user`. Before the fix this declined and fell back to route 379's GET login
     * shell — benign here, but inconsistent with the other three oracles, where the same shape of gap
     * (owns_path claims the path; a stricter match declines) falls through to a genuinely dangerous
     * corpus bundle. Keeping all four oracles' match as permissive as owns_path is what closes that.
     */
    public function test_post_with_missing_or_empty_body_still_dispatches_the_oracle(): void
    {
        $emu = $this->isolated();
        foreach ([
            'missing user field' => json_encode(['password' => 'x']),
            'empty body' => '',
            'empty JSON object' => '{}',
        ] as $label => $body) {
            $r = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $body));
            self::assertNotNull($r, $label);
            self::assertSame(401, $r->status, $label);
            self::assertSame(self::EXPECTED_BODY, $r->body, $label);
        }
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
