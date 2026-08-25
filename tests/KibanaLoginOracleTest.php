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
 * The request-aware Kibana /internal/security/login credential emulator (attack rule 101,
 * WP-Phase-2b), coherent with route 372's app-shell bundle (Kibana 7.17.18). The real endpoint's
 * xsrf interceptor runs BEFORE any body parsing, so this rule gates on path + method only and never
 * reads the request body: `behavior: branch` picks the response purely off the `kbn-xsrf` HEADER's
 * presence — absent/empty -> 400 "must contain a kbn-xsrf header"; present -> 401 security_exception.
 * Pins the load-bearing safety invariants: zero-reflection (a FIXED persona username `admin` in the
 * 401 body — the submitted username never surfaces, unlike real Kibana's double-reflection),
 * zero-execution (no body field is ever read), never-authenticate (no Set-Cookie in either branch),
 * and POST-gated (any other verb misses this rule's method condition).
 *
 * owns_path IS LOAD-BEARING here (unlike a rule with no real-store collision): the REAL compiled
 * corpus resources/compiled/nuclei-index.full.php — what PhpArrayStore::fromPackage() loads in prod —
 * has a live exact-store bundle keyed EXACTLY `POST /internal/security/login` (nuclei template
 * `elasticsearch-default-login`): a fake LOGIN-SUCCESS, status 200 with a `Set-Cookie: sid=`
 * header-watch. Route 372 (route-kibana) is NOT the collision — it keys only the `exposed-kibana`
 * needle, bound to `GET /app/kibana(/)`, never this path. Without owns_path, classify() would resolve
 * a POST here to that dangerous corpus bundle instead of this oracle; see
 * test_classify_overrides_the_live_elasticsearch_default_login_bundle and
 * test_served_response_is_the_oracle_never_the_elasticsearch_login_success_bundle below, which drive
 * a full Honeypot over the REAL corpus (not the compiled attack rules alone) to pin the override.
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

    /**
     * A full Honeypot over the REAL compiled corpus (nuclei-index.full.php — what
     * PhpArrayStore::fromPackage() loads in prod), not the small test fixture. This is the only way
     * to reproduce the live `POST /internal/security/login` = elasticsearch-default-login collision
     * owns_path overrides; mirrors WpXmlrpcEmulatorTest::fullEngine(), with mode='respond' (+ a
     * permissive gate) when the test also needs the actual served bytes, not just the verdict.
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

    // --- REGRESSION: owns_path overrides a LIVE dangerous corpus bundle at this exact path ----------

    /**
     * The real compiled corpus (nuclei-index.full.php) has a bundle keyed EXACTLY
     * `POST /internal/security/login` — nuclei template `elasticsearch-default-login`, a fake
     * LOGIN-SUCCESS (status 200, `Set-Cookie: sid=`). Without owns_path, classify() would resolve
     * this request to a ROUTE handle onto that bundle (Verdict::SCANNER_PROBE), not this oracle. This
     * pins that classify() instead returns the ATTACK_CLASS verdict with THIS rule's handle, so a
     * future owns_path removal or corpus/index rebuild that drops the override can't silently regress
     * into serving a fake authenticated session.
     */
    public function test_classify_overrides_the_live_elasticsearch_default_login_bundle(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(
            FakeHandle::KIND_ATTACK,
            $verdict->fakeHandle->kind,
            'must be the attack-tier handle, not a route handle onto the elasticsearch-default-login bundle'
        );
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    /**
     * The actual served bytes (via the full respond() facade over the REAL corpus, so the kbn-xsrf
     * branch is genuinely evaluated against the live request) must be this oracle's response in both
     * branches — never the elasticsearch-default-login bundle's 200 + `Set-Cookie: sid=` fake
     * login-success, whatever the kbn-xsrf header carries.
     */
    public function test_served_response_is_the_oracle_never_the_elasticsearch_login_success_bundle(): void
    {
        $engine = $this->fullEngine(true);

        $present = $engine->respond(new RequestContext('POST', self::PATH, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($present);
        self::assertSame(401, $present->status);
        self::assertSame(self::BODY_401, $present->body);
        self::assertArrayNotHasKey('Set-Cookie', $present->headers);
        self::assertArrayNotHasKey('set-cookie', $present->headers);
        self::assertStringNotContainsString('sid=', implode(' ', $present->headers));

        $absent = $engine->respond(new RequestContext('POST', self::PATH, '', [], $this->loginBody('root')));
        self::assertNotNull($absent);
        self::assertSame(400, $absent->status);
        self::assertSame(self::BODY_400, $absent->body);
        self::assertArrayNotHasKey('Set-Cookie', $absent->headers);
        self::assertArrayNotHasKey('set-cookie', $absent->headers);
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

    // --- REGRESSION: adversarial canonical-variant requests must still win, never fall through -------

    /**
     * WP-Phase-2b safety fix: PathNormalizer::ownershipKey() lower-cases the path and strips a
     * trailing slash, so ownsPath() returns true for a case/trailing-slash/method variant of the
     * owned path — but the oracle's OWN match used to be stricter (anchored path with no trailing
     * slash, `ci: false`, method `ci: false`). A variant request then made ownsPath() true (entering
     * the override) while matchRule() declined, so classify() fell through to resolveEntry(), which
     * re-resolved the SAME variant onto the live `elasticsearch-default-login` bundle (200,
     * `Set-Cookie: sid=`) — a fake LOGIN-SUCCESS. The oracle's match is now as permissive as
     * ownsPath's canonical form, so every variant below must win instead: ATTACK_CLASS + KIND_ATTACK,
     * and the served bytes must be this oracle's own response, never the bundle's 200/sid= cookie.
     *
     * @dataProvider adversarialVariantProvider
     */
    public function test_adversarial_variants_win_never_the_elasticsearch_login_success_bundle(
        string $method,
        string $path
    ): void {
        $verdict = $this->fullEngine()->classify(
            new RequestContext($method, $path, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification, "{$method} {$path}");
        self::assertNotNull($verdict->fakeHandle, "{$method} {$path}");
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind, "{$method} {$path}: must be the attack-tier handle, not a route handle onto elasticsearch-default-login");
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId, "{$method} {$path}");

        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext($method, $path, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($r, "{$method} {$path}");
        self::assertSame(401, $r->status, "{$method} {$path}: must not be the bundle's 200 login-success");
        self::assertSame(self::BODY_401, $r->body, "{$method} {$path}");
        self::assertArrayNotHasKey('Set-Cookie', $r->headers, "{$method} {$path}");
        self::assertArrayNotHasKey('set-cookie', $r->headers, "{$method} {$path}");
        self::assertStringNotContainsString('sid=', implode(' ', $r->headers), "{$method} {$path}");
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
            'mixed-case path' => ['POST', '/Internal/security/login'],
            'lowercase method' => ['post', self::PATH],
        ];
    }

    /**
     * A query string appended to a multi-slash path must not change the match: `in: path`/`in:
     * method` read $r->path/$r->method only, never $r->query (PathNormalizer::ownershipKey() is
     * likewise query-blind — ownsPath() is called with $r->path alone). Reproduces the second-review
     * repro shape (`POST /login//?a=b`) against this oracle's own path.
     */
    public function test_query_appended_to_a_multi_slash_path_still_wins(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', self::PATH . '//', 'a=b', ['kbn-xsrf' => 'true'], $this->loginBody('root')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $verdict->fakeHandle->kind);
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);

        $engine = $this->fullEngine(true);
        $r = $engine->respond(new RequestContext('POST', self::PATH . '//', 'a=b', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
        self::assertNotNull($r);
        self::assertSame(401, $r->status);
        self::assertSame(self::BODY_401, $r->body);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    /**
     * The MULTI-trailing-slash regression, pinned at BOTH the default (high) and critical severity
     * ceiling — Part 1 of the WP-Phase-2b second-review fix (the `/*$` path regex) makes matchRule()
     * itself win outright for this path family (no owns_path-decline fallthrough involved), so the
     * ceiling should never matter; this test proves that rather than assuming it.
     */
    public function test_multi_trailing_slash_wins_at_every_severity_ceiling(): void
    {
        foreach (['high', 'critical'] as $ceiling) {
            foreach (['//', '///'] as $slashes) {
                $engine = $this->fullEngine(true, $ceiling);
                $path = self::PATH . $slashes;
                $r = $engine->respond(new RequestContext('POST', $path, '', ['kbn-xsrf' => 'true'], $this->loginBody('root')));
                $label = "POST {$path} @ceiling={$ceiling}";

                self::assertNotNull($r, $label);
                self::assertSame(401, $r->status, $label);
                self::assertSame(self::BODY_401, $r->body, $label);
                self::assertArrayNotHasKey('Set-Cookie', $r->headers, $label);
                self::assertStringNotContainsString('sid=', implode(' ', $r->headers), $label);
            }
        }
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
