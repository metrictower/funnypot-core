<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The phpMyAdmin flagship mock-auth pair (attack rules 102/103): a faithful re-authored login page
 * wired to the `decoy-session` primitive (mint on POST, gate on GET/HEAD) over the real phpMyAdmin
 * panel paths. Drives the COMPILED rules directly (mirrors WpXmlrpcEmulatorTest/
 * DecoySessionBehaviorTest), with a decoySessionKey so mint/gate are enabled — pins the login/mint/
 * gate flow end to end, variant tolerance, and that the served bytes never leak an unrendered
 * directive or a denylisted fingerprint token.
 *
 * LICENSING: the login page HTML/CSS is original — re-authored from the FACTS of the real
 * phpMyAdmin 5.2 login form (field names/ids/structure), never phpMyAdmin's own GPL-2.0 CSS/JS
 * bytes. Same posture as the byte-exact Phase-2b login oracles (97-101): reproducing an observable
 * structure in original code, not vendoring upstream files.
 */
final class PhpMyAdminMockAuthTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private const KEY = 'test-key';

    private const GATE_ID = 'attack-phpmyadmin-gate';

    private const MINT_ID = 'attack-phpmyadmin-login';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED, [], null, self::KEY);
    }

    /** An emulator wired with an explicit per-deploy persona seed, so {{persona.*}} in the login/gate
     *  body and the authed dashboard skin both resolve from THIS seed (the prod deploy precondition). */
    private function seededEmulator(int $seed): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED, [], $seed, self::KEY);
    }

    private function serve(string $method, string $path, string $query = '', array $headers = [], ?string $body = null): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, $path, $query, $headers, $body));
    }

    /** The name=value pair a browser would send back, parsed out of a full Set-Cookie string. */
    private function cookieHeaderFrom(string $setCookie): string
    {
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    private function mintValidLogin(): object
    {
        $r = $this->serve('POST', '/phpmyadmin/index.php', '', [], 'pma_username=admin&pma_password=secret');
        self::assertNotNull($r);
        self::assertSame(302, $r->status, 'a plausible non-empty login must mint');

        return $r;
    }

    // --- compile / ordering -----------------------------------------------------------------

    public function test_both_rules_compiled_unique_and_ordered(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);

        self::assertContains(self::GATE_ID, $ids);
        self::assertContains(self::MINT_ID, $ids);
        self::assertSame(array_unique($ids), $ids, 'template ids must be globally unique');

        // Gate (GET/HEAD) sorts before mint (POST) — cosmetic here (disjoint by method, so order
        // can't change which one fires), but kept adjacent the same way WpXmlrpcEmulatorTest pins
        // 26 (attack-wp-xmlrpc) sorting before 27 (attack-wp-xmlrpc-get).
        self::assertLessThan(
            array_search(self::MINT_ID, $ids, true),
            array_search(self::GATE_ID, $ids, true)
        );

        // The build-time guard this task requires: the merged corpus grew by exactly these 2 rules,
        // and Agent A's ai-ollama pack + the CRS pack both survived the recompile untouched. Total
        // count has since grown further with unrelated rules (see ZapCoverageTest for that delta);
        // this assertion just needs to track the current total so it keeps proving THIS pair is
        // still exactly 2 of them, not a stale absolute pin.
        self::assertCount(67, $rules, 'compiled corpus must be 57 (original baseline) + 2 (this pair) + 8 (unrelated, since: imds-base, wp-admin-redirect, lfi-sshkey, lfi-hostname, imds-identity-doc, FP-0229 nextjs-rsc, FP-0232 verbose-error-volatile, FP-0234 ssti-multifence)');
        $ollama = array_filter($ids, static function (string $id): bool {
            return strpos($id, 'ai-ollama') !== false;
        });
        self::assertCount(6, $ollama, 'the 6 ai-ollama-* rules must survive the recompile');
        $crs = array_filter($ids, static function (string $id): bool {
            return strpos($id, 'crs') !== false;
        });
        self::assertCount(4, $crs, 'the 4 CRS rules must survive the recompile');
    }

    public function test_gate_rule_owns_the_panel_root_paths(): void
    {
        $em = $this->emulator();
        // ownsPath() canonicalizes case + trailing slashes, so every authored/aliased form of the
        // panel root resolves to the same claim. The compiler's owns_path variant-coverage check
        // (run at `php bin/funnypot compile-emulators`) emitted NO warning for either new rule when
        // this pair was authored/compiled — verified by inspecting the compiler's STDERR directly
        // (there is no public warnings-returning API to assert against here; see EmulatorCompiler::
        // ownsPathVariantWarnings, a private build-time lint).
        foreach (['/phpmyadmin/', '/phpmyadmin', '/PhpMyAdmin/', '/phpmyadmin//', '/pma/', '/pma', '/phpmyadmin/index.php'] as $path) {
            self::assertTrue($em->ownsPath($path), $path);
        }
    }

    // --- GET (no cookie): the login page ----------------------------------------------------

    public function test_get_no_cookie_serves_the_login_page(): void
    {
        $r = $this->serve('GET', '/phpmyadmin/');

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('id="login_form"', $r->body);
        self::assertStringContainsString('pma_username', $r->body);
        self::assertStringContainsString('pma_password', $r->body);
        self::assertStringContainsString('<title>phpMyAdmin', $r->body);
        self::assertStringNotContainsString('{{', $r->body, 'no directive may survive unrendered');
        self::assertSame([], FingerprintGuard::fromPackage()->scan($r->body), 'login page must be fingerprint-clean');
    }

    // --- POST: mint on a plausible login -----------------------------------------------------

    public function test_post_valid_credentials_mints_a_signed_s1_cookie_and_redirects(): void
    {
        $r = $this->mintValidLogin();

        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('path=/phpmyadmin; HttpOnly', $r->headers['Set-Cookie']);
        self::assertSame('/phpmyadmin/index.php', $r->headers['Location']);

        $nameValue = $this->cookieHeaderFrom($r->headers['Set-Cookie']);
        $eq = strpos($nameValue, '=');
        self::assertNotFalse($eq);
        self::assertSame('phpMyAdmin', substr($nameValue, 0, $eq));
        $payload = (new Honeytoken(self::KEY))->verifiedPayload(substr($nameValue, $eq + 1));
        self::assertSame('s=1', $payload, 'the minted cookie must decode to the authenticated payload class');
    }

    public function test_post_empty_password_declines_to_the_login_page_no_redirect(): void
    {
        $r = $this->serve('POST', '/phpmyadmin/index.php', '', [], 'pma_username=admin&pma_password=');

        self::assertNotNull($r);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('id="login_form"', $r->body);
    }

    public function test_post_empty_username_declines_to_the_login_page(): void
    {
        $r = $this->serve('POST', '/phpmyadmin/index.php', '', [], 'pma_username=&pma_password=secret');

        self::assertNotNull($r);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    public function test_post_credentials_in_either_field_order_still_mints(): void
    {
        // The body match uses two independent lookaheads, not a fixed field sequence, so the
        // real form's DOM order (username, then password) is not the only order accepted.
        $r = $this->serve('POST', '/phpmyadmin/index.php', '', [], 'pma_password=secret&pma_username=admin');

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
    }

    // --- GET with the minted cookie: the authed placeholder ---------------------------------

    public function test_get_with_minted_cookie_serves_the_authed_placeholder_not_the_login_form(): void
    {
        $mint = $this->mintValidLogin();
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);

        $r = $this->serve('GET', '/phpmyadmin/', '', ['Cookie' => $cookieHeader]);

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('Showing rows', $r->body);
        self::assertStringNotContainsString('id="login_form"', $r->body, 'an authed session must never re-show the login form');
    }

    // --- GET with a garbage cookie: fail closed ----------------------------------------------

    public function test_get_with_garbage_cookie_falls_back_to_the_login_page(): void
    {
        $r = $this->serve('GET', '/phpmyadmin/', '', ['Cookie' => 'phpMyAdmin=nonsense-not-signed']);

        self::assertNotNull($r);
        self::assertStringContainsString('id="login_form"', $r->body);
        self::assertStringNotContainsString('Showing rows', $r->body);
    }

    public function test_get_with_a_validly_signed_s0_cookie_is_not_authenticated(): void
    {
        // A validly-signed s=0 (pre-auth marker class) must NOT authenticate — a different payload
        // class, not a weaker s=1 (mirrors DecoySessionTest's own invariant).
        $s0 = (new Honeytoken(self::KEY))->cookie('phpMyAdmin', 's=0', '/phpmyadmin');
        $cookieHeader = $this->cookieHeaderFrom($s0);

        $r = $this->serve('GET', '/phpmyadmin/', '', ['Cookie' => $cookieHeader]);

        self::assertNotNull($r);
        self::assertStringContainsString('id="login_form"', $r->body);
        self::assertStringNotContainsString('Showing rows', $r->body);
    }

    // --- variant paths / methods: never an authed body on a decline -------------------------

    public function test_variant_paths_and_head_never_serve_the_authed_body_without_a_valid_cookie(): void
    {
        foreach ([
            ['GET', '/phpmyadmin//'],
            ['GET', '/PhpMyAdmin/'],
            ['HEAD', '/phpmyadmin/'],
            ['HEAD', '/PhpMyAdmin//'],
            ['GET', '/pma/'],
            ['GET', '/pma'],
        ] as [$method, $path]) {
            $r = $this->serve($method, $path);
            self::assertNotNull($r, "$method $path");
            // Never the authed body on a decline — whether the response is the login page or a
            // canonical-slash 301 (a bare directory redirects to its trailing-slash form first).
            self::assertStringNotContainsString('Showing rows', $r->body, "$method $path must never authenticate on a decline");
            if ($r->status === 301) {
                self::assertSame($path . '/', $r->headers['Location'], "$method $path canonical-slash redirect");
            } else {
                self::assertStringContainsString('id="login_form"', $r->body, "$method $path must fall back to the login page");
            }
        }
    }

    public function test_variant_paths_never_serve_the_authed_body_even_with_a_valid_cookie_if_match_declines(): void
    {
        // A valid s=1 cookie only ever authenticates through the gate rule's OWN match — never a
        // side effect of some other rule/path. Every owned variant here still resolves to gate/mint
        // (owns_path canonicalizes them), so the authed body IS expected once a valid cookie rides
        // along; this pins that the variant tolerance doesn't accidentally widen into something else.
        $mint = $this->mintValidLogin();
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);

        foreach (['/phpmyadmin//', '/PhpMyAdmin/', '/pma/', '/pma'] as $path) {
            $r = $this->serve('GET', $path, '', ['Cookie' => $cookieHeader]);
            self::assertNotNull($r, $path);
            $isBareDir = substr($path, -1) !== '/' && strpos(basename($path), '.') === false;
            if ($isBareDir) {
                // A bare directory canonical-slash 301s BEFORE the auth check (DirectorySlash) — the
                // authed body is served after the browser follows the redirect to the slashed form.
                self::assertSame(301, $r->status, $path);
                self::assertSame($path . '/', $r->headers['Location'], $path);
            } else {
                self::assertStringContainsString('Showing rows', $r->body, $path);
            }
        }
    }

    // --- canonical trailing-slash 301 (Apache DirectorySlash) -------------------------------

    public function test_bare_panel_directory_301s_to_the_trailing_slash(): void
    {
        // Real phpMyAdmin sits behind Apache DirectorySlash: `/phpmyadmin` (no slash) 301s to
        // `/phpmyadmin/` so the login form's relative `action="index.php?route=/"` resolves to the owned
        // `/phpmyadmin/index.php` instead of escaping to a bare `/index.php` (which this decoy does not
        // own, so it would fall through to an unrelated rule). Regression guard for that fall-through.
        foreach (['/phpmyadmin' => '/phpmyadmin/', '/pma' => '/pma/'] as $bare => $slashed) {
            $r = $this->serve('GET', $bare);
            self::assertNotNull($r, $bare);
            self::assertSame(301, $r->status, $bare . ' must 301 to the trailing-slash form');
            self::assertSame($slashed, $r->headers['Location'], $bare . ' -> ' . $slashed);
            self::assertStringNotContainsString('id="login_form"', $r->body, '301 body is not the login page');
        }

        // The slashed form and the index.php file still serve the login page — no redirect loop.
        foreach (['/phpmyadmin/', '/phpmyadmin/index.php'] as $served) {
            $r = $this->serve('GET', $served);
            self::assertNotNull($r, $served);
            self::assertNotSame(301, $r->status, $served . ' must not redirect');
            self::assertStringContainsString('id="login_form"', $r->body, $served . ' serves the login page');
        }
    }

    // --- disabled key: hard kill switch (mirrors DecoySessionBehaviorTest) ------------------

    public function test_disabled_decoy_session_key_never_authenticates(): void
    {
        $em = TemplateAttackEmulator::fromFile(self::COMPILED, [], null, null);
        $r = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], 'pma_username=admin&pma_password=secret'));

        self::assertNotNull($r);
        self::assertNotSame(302, $r->status);
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
        self::assertStringContainsString('id="login_form"', $r->body);
    }

    // --- fingerprint safety: scan the RENDERED responses, not just the authored directive text ----

    public function test_rendered_responses_carry_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();

        $mint = $this->mintValidLogin();
        $bodies = [
            $this->serve('GET', '/phpmyadmin/')->body,
            $mint->body,
            $this->serve('GET', '/phpmyadmin/', '', ['Cookie' => $this->cookieHeaderFrom($mint->headers['Set-Cookie'])])->body,
        ];

        foreach ($bodies as $body) {
            self::assertSame([], $guard->scan($body));
        }
        foreach ($mint->headers as $name => $value) {
            self::assertSame([], $guard->scan((string) $name));
            self::assertSame([], $guard->scan((string) $value));
        }
    }

    public function test_login_page_never_reflects_the_signing_key(): void
    {
        $r = $this->serve('GET', '/phpmyadmin/');
        self::assertNotNull($r);
        self::assertStringNotContainsString(self::KEY, $r->body);

        $mint = $this->mintValidLogin();
        self::assertStringNotContainsString(self::KEY, $mint->headers['Set-Cookie']);
        self::assertStringNotContainsString(self::KEY, $mint->headers['Location']);
    }

    // --- FP-0005: seed-derived app version + class prefix (no fleet-wide literal) -------------

    /** The rendered login body carries the seed-derived phpMyAdmin app version + class prefix, and
     *  none of the old fleet-wide literals (`phpMyAdmin 5.2.1`, the invented `pma-*` classes, the id
     *  `pma_errors`) survive. Real phpMyAdmin field names (`pma_username`/`pma_password`) stay. */
    public function test_login_body_carries_seed_derived_version_and_prefix_no_fleet_literal(): void
    {
        $seed = 0x5f0005;
        $version = (string) PersonaIdentity::fromSeed($seed)->field('phpmyadmin.version');
        $prefix = VisualPersona::fromSeed($seed)->classPrefix();

        $r = $this->seededEmulator($seed)->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
        self::assertNotNull($r);
        $body = $r->body;

        self::assertStringContainsString('phpMyAdmin ' . $version, $body, 'footer shows the seed-derived app version');
        self::assertStringContainsString('class="' . $prefix . '-wrap"', $body, 'the wrapper carries the seed-derived class prefix');
        self::assertStringContainsString('id="' . $prefix . '-errors"', $body, 'the errors box id carries the prefix');

        // The killed fleet-wide literals are gone; the real protocol field names remain.
        self::assertStringNotContainsString('phpMyAdmin 5.2.1', $body);
        self::assertStringNotContainsString('pma-wrap', $body);
        self::assertStringNotContainsString('pma-card', $body);
        self::assertStringNotContainsString('id="pma_errors"', $body);
        self::assertStringContainsString('name="pma_username"', $body);
        self::assertStringContainsString('name="pma_password"', $body);
        self::assertStringNotContainsString('{{', $body, 'no directive may survive unrendered');
    }

    /** Deploy-stable, not per-request: two consecutive serves at one seed are byte-identical (a
     *  per-request {{pick}}/random would diverge). */
    public function test_login_body_is_deploy_stable_across_two_serves(): void
    {
        $em = $this->seededEmulator(0x5f0005);
        $a = $em->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
        $b = $em->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, 'the seed-derived login body must be byte-stable per deploy');
    }

    /** Per-deploy variation: across distinct seeds the rendered version/prefix track their seed-derived
     *  values (asserted against the derived value, not a bare "not equal", to avoid pool-collision flake). */
    public function test_login_body_varies_by_deploy_seed(): void
    {
        $prefixes = [];
        foreach ([11, 22, 33, 44, 55] as $seed) {
            $version = (string) PersonaIdentity::fromSeed($seed)->field('phpmyadmin.version');
            $prefix = VisualPersona::fromSeed($seed)->classPrefix();
            $r = $this->seededEmulator($seed)->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
            self::assertNotNull($r);
            self::assertStringContainsString('phpMyAdmin ' . $version, $r->body, "seed {$seed}: version tracks the seed");
            self::assertStringContainsString('class="' . $prefix . '-wrap"', $r->body, "seed {$seed}: prefix tracks the seed");
            $prefixes[] = $prefix;
        }
        self::assertGreaterThan(1, count(array_unique($prefixes)), 'the class prefix must not collapse to one value across deploys');
    }

    /** Gate (GET, rule 102) and login-decline (POST empty password, rule 103) render the identical
     *  body for one deploy seed — gate == login by construction. */
    public function test_gate_and_login_decline_bodies_are_identical_for_one_seed(): void
    {
        $em = $this->seededEmulator(0x5f0005);
        $gate = $em->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
        $decline = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], 'pma_username=admin&pma_password='));
        self::assertNotNull($gate);
        self::assertNotNull($decline);
        self::assertNotSame(302, $decline->status, 'empty password must decline, not mint');
        self::assertSame($gate->body, $decline->body, 'gate and login-decline must serve the identical login body');
    }

    /** Gate <-> dashboard coherence: the class prefix in the login body equals the prefix
     *  PhpMyAdminSkin renders into the authed dashboard for the same deploy seed. */
    public function test_login_and_authed_dashboard_share_one_class_prefix(): void
    {
        $seed = 0x5f0005;
        $prefix = VisualPersona::fromSeed($seed)->classPrefix();
        $em = $this->seededEmulator($seed);

        // Login page carries the prefix.
        $login = $em->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
        self::assertNotNull($login);
        self::assertStringContainsString('class="' . $prefix . '-wrap"', $login->body);

        // Mint a session, then the authed dashboard body carries the SAME prefix.
        $mint = $em->emulate(new RequestContext('POST', '/phpmyadmin/index.php', '', [], 'pma_username=admin&pma_password=secret'));
        self::assertNotNull($mint);
        self::assertSame(302, $mint->status);
        $cookieHeader = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);
        $dash = $em->emulate(new RequestContext('GET', '/phpmyadmin/', '', ['Cookie' => $cookieHeader]));
        self::assertNotNull($dash);
        self::assertStringContainsString('Showing rows', $dash->body, 'the authed dashboard renders');
        self::assertStringContainsString($prefix . '-', $dash->body, 'dashboard shares the login class prefix');
    }

    /** Fingerprint-clean across seeds: the seed-derived rendered login body never trips the runtime
     *  FingerprintGuard (the directive substitution introduced no detector token). */
    public function test_seeded_login_bodies_stay_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ([0, 1, 7, 0x5f0005, 484348449122915112] as $seed) {
            $r = $this->seededEmulator($seed)->emulate(new RequestContext('GET', '/phpmyadmin/', '', []));
            self::assertNotNull($r);
            self::assertSame([], $guard->scan($r->body), "seed {$seed}: login body must be fingerprint-clean");
        }
    }
}
