<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\Fake\FakeSecrets;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0271 — the authed WordPress admin dashboard behind the wp-login mock-auth mint. Drives the
 * COMPILED rules directly (mirrors PhpMyAdminMockAuthTest), with a decoySessionKey so mint (rule 97)
 * and gate (rule 104) are live. Pins the whole flow AND the paramount safety invariant: the authed
 * dashboard is UNREACHABLE without a validly HMAC-minted authenticated decoy session for THIS deploy —
 * a forged/tampered/wrong-key/absent/pre-auth/cross-seed cookie falls through to the pinned 302 (byte-identical to today), and a
 * key-unset deploy is byte-identical to today.
 *
 * LICENSING: the dashboard HTML/CSS is original — a hand-authored lookalike of the wp-admin shell
 * (structure/class vocabulary), never WordPress's own GPL bytes (same posture as the login oracles).
 */
final class WpAdminMockAuthTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private const MINT_ID = 'attack-wp-login';

    private const GATE_ID = 'attack-wp-admin-redirect';

    /** The byte-for-byte 302 target a declined /wp-admin gate emits (ZapCoverageTest's pin). */
    private const WP_ADMIN_LOCATION = '/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1';

    private const SEED = 484348449122915112;

    /** Keyed emulator wired with an explicit per-deploy persona seed, so {{persona.*}} in the cookie
     *  name / login body and the authed dashboard both resolve from THIS seed (the prod precondition). */
    private function seededEmulator(int $seed = self::SEED): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED, [], $seed, self::KEY);
    }

    /** The per-deploy cookie name rule 97 mints and rule 104 gates for a given seed. */
    private function cookieName(int $seed): string
    {
        return 'wordpress_logged_in_' . (string) PersonaIdentity::fromSeed($seed)->field('wordpress.cookieHash');
    }

    /** The name=value pair a browser sends back, parsed out of a full Set-Cookie string. */
    private function cookieHeaderFrom(string $setCookie): string
    {
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    private function mint(TemplateAttackEmulator $em, string $body = 'log=admin&pwd=hunter2'): ?object
    {
        return $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], $body));
    }

    /** Full mint -> replay-cookie -> GET /wp-admin/ loop for one seed. */
    private function authedGet(int $seed = self::SEED, string $path = '/wp-admin/', string $query = ''): object
    {
        $em = $this->seededEmulator($seed);
        $mint = $this->mint($em);
        self::assertNotNull($mint);
        self::assertSame(302, $mint->status);
        $cookie = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);
        $r = $em->emulate(new RequestContext('GET', $path, $query, ['Cookie' => $cookie]));
        self::assertNotNull($r);

        return $r;
    }

    // --- MINT --------------------------------------------------------------------------------

    public function test_plausible_wp_login_post_mints_302_with_signed_cookie_to_wp_admin(): void
    {
        $mint = $this->mint($this->seededEmulator());

        self::assertNotNull($mint);
        self::assertSame(302, $mint->status, 'a plausible non-empty login must mint');
        self::assertSame('/wp-admin/', $mint->headers['Location'], 'mint redirects to the fixed wp-admin literal');
        self::assertArrayHasKey('Set-Cookie', $mint->headers);

        $nameValue = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);
        $eq = strpos($nameValue, '=');
        self::assertNotFalse($eq);
        self::assertSame($this->cookieName(self::SEED), substr($nameValue, 0, $eq), 'cookie name is the per-deploy wordpress_logged_in_<hash>');
        $payload = (new Honeytoken(self::KEY))->verifiedPayload(substr($nameValue, $eq + 1));
        self::assertSame(DecoySessionPayloads::authenticated(self::SEED), $payload, 'the minted cookie must decode to this deploy\'s authenticated payload');
    }

    public function test_empty_or_implausible_credentials_decline_to_login_error_page(): void
    {
        foreach (['log=admin&pwd=', 'log=&pwd=secret', 'log=' . rawurlencode('<script>x') . '&pwd=secret', ''] as $body) {
            $r = $this->mint($this->seededEmulator(), $body);
            self::assertNotNull($r, $body);
            self::assertNotSame(302, $r->status, "[{$body}] must decline, not mint");
            self::assertSame(200, $r->status, "[{$body}] declines to the 200 login-error page");
            self::assertArrayNotHasKey('Location', $r->headers, $body);
            // The base page keeps only the inert wordpress_test_cookie a real server also sets pre-auth;
            // NO minted authenticated session cookie (never a wordpress_logged_in auth cookie).
            $setCookie = (string) ($r->headers['Set-Cookie'] ?? '');
            self::assertStringNotContainsString('wordpress_logged_in_', $setCookie, "[{$body}] no minted session cookie");
            self::assertStringContainsString('wordpress_test_cookie', $setCookie, $body);
            self::assertStringContainsString('login_error', $r->body, $body);
            self::assertStringNotContainsString('<script>', $r->body, 'no crafted username is ever reflected');
        }
    }

    public function test_mint_location_is_a_fixed_literal_a_crafted_redirect_to_cannot_steer(): void
    {
        $mint = $this->mint($this->seededEmulator(), 'log=admin&pwd=secret&redirect_to=https://evil.example/');

        self::assertNotNull($mint);
        self::assertSame(302, $mint->status);
        self::assertSame('/wp-admin/', $mint->headers['Location'], 'a crafted redirect_to must never steer the Location');
    }

    // --- GATE: the no-unauth-leak proofs -----------------------------------------------------

    public function test_valid_minted_cookie_renders_authed_dashboard_through_wordpress_skin(): void
    {
        $r = $this->authedGet();

        self::assertSame(200, $r->status);
        // wp-admin shell markers.
        self::assertStringContainsString('id="wpadminbar"', $r->body);
        self::assertStringContainsString('id="adminmenu"', $r->body);
        self::assertStringContainsString('At a Glance', $r->body);
        self::assertStringContainsString('wp-list-table', $r->body);
        self::assertStringContainsString('Howdy,', $r->body);
        // persona coherence: the site company + the WP core version this deploy claims.
        $persona = VisualPersona::fromSeed(self::SEED);
        self::assertStringContainsString($persona->company(), $r->body, 'dashboard names the persona company');
        self::assertStringContainsString('WordPress ' . (string) $persona->identity()->field('wordpress.version'), $r->body);
        // the loot table's own headers.
        foreach (['Username', 'Name', 'Email', 'Role', 'API key'] as $col) {
            self::assertStringContainsString('<th>' . $col . '</th>', $r->body, $col);
        }
    }

    public function test_absent_cookie_falls_back_to_login_redirect_with_no_authed_bytes(): void
    {
        // No cookie -> the pinned 302 to wp-login, byte-identical to today, and NO authed content.
        $r = $this->seededEmulator()->emulate(new RequestContext('GET', '/wp-admin/'));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location']);
        self::assertSame('', $r->body, 'the decline is a bodyless 302, never a dashboard');
        self::assertStringNotContainsString('wp-list-table', $r->body);
        self::assertStringNotContainsString('Howdy,', $r->body);
    }

    public function test_forged_and_tampered_cookies_never_render_authed_content(): void
    {
        $em = $this->seededEmulator();
        $name = $this->cookieName(self::SEED);

        // A valid authenticated token minted under a DIFFERENT key (attacker cannot know the server key).
        $wrongKey = (new DecoySession('a-completely-different-key', self::SEED))->mintCookie($name, '/');
        // A structurally valid value whose signature is truncated.
        $validValue = substr($this->cookieHeaderFrom((new DecoySession(self::KEY, self::SEED))->mintCookie($name, '/')), strlen($name) + 1);
        $truncated = $name . '=' . substr($validValue, 0, -4);

        $forged = [
            'garbage'      => $name . '=nonsense-not-signed',
            'no dot'       => $name . '=s%3D1',
            'wrong key'    => $this->cookieHeaderFrom($wrongKey),
            'truncated'    => $truncated,
            'wrong name'   => 'wordpress_logged_in_deadbeef=' . $validValue,
        ];

        foreach ($forged as $label => $cookie) {
            $r = $em->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $cookie]));
            self::assertNotNull($r, $label);
            self::assertSame(302, $r->status, "{$label}: a non-authenticated cookie must fall through to the 302");
            self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location'], $label);
            self::assertStringNotContainsString('wp-list-table', $r->body, "{$label}: never an authed dashboard");
            self::assertStringNotContainsString('At a Glance', $r->body, $label);
        }
    }

    public function test_signed_pre_auth_cookie_is_not_authenticated(): void
    {
        // A validly-signed pre-auth marker must NOT authenticate — a different payload class. Minted at
        // this deploy's seed so it is a genuinely current pre-auth value.
        $name = $this->cookieName(self::SEED);
        $preAuth = $this->cookieHeaderFrom((new DecoySession(self::KEY, self::SEED))->preAuthCookie($name, '/'));

        $r = $this->seededEmulator()->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $preAuth]));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location']);
        self::assertStringNotContainsString('wp-list-table', $r->body);
    }

    public function test_no_key_configured_disables_both_mint_and_gate_byte_identically(): void
    {
        // Unkeyed emulator: the decoy-session behavior declines before any DecoySession is built, so the
        // POST oracle and the /wp-admin redirect are byte-identical to today.
        $unkeyed = TemplateAttackEmulator::fromFile(self::COMPILED, [], self::SEED, null);

        $post = $unkeyed->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=secret'));
        self::assertNotNull($post);
        self::assertSame(200, $post->status, 'no key: the POST is the login-error oracle, never a mint');
        self::assertArrayNotHasKey('Location', $post->headers);
        self::assertStringNotContainsString('wordpress_logged_in_', (string) ($post->headers['Set-Cookie'] ?? ''));

        // Even presenting a validly minted authenticated cookie: with no key the gate cannot verify, so it declines.
        $name = $this->cookieName(self::SEED);
        $cookie = $this->cookieHeaderFrom((new DecoySession(self::KEY, self::SEED))->mintCookie($name, '/'));
        $get = $unkeyed->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $cookie]));
        self::assertNotNull($get);
        self::assertSame(302, $get->status);
        self::assertSame(self::WP_ADMIN_LOCATION, $get->headers['Location']);
        self::assertSame('', $get->body);
    }

    // --- SIGNAL: honeytoken-retrieval fold over the REAL corpus ------------------------------

    public function test_authed_wp_admin_get_folds_honeytoken_retrieval_signal(): void
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config('detect', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, true);
        $config->decoySessionKey = self::KEY;
        $engine = new Honeypot($store, $config);

        // DecoySessionProbe is name-agnostic: ANY cookie value verifying to this deploy's authenticated
        // payload folds the signal. Mint at the engine's snapshotted deploy seed (Config::deploySeed()).
        $cookie = $this->cookieHeaderFrom((new DecoySession(self::KEY, $config->deploySeed()))->mintCookie('sess', '/'));
        $v = $engine->classify(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $cookie]), SiteProfile::empty());

        self::assertSame(Verdict::ATTACK_CLASS, $v->classification, 'stays the attack-class verdict');
        self::assertNotNull($v->fakeHandle);
        self::assertSame(self::GATE_ID, $v->fakeHandle->ruleId, 'the served handle is still rule 104, untouched by the fold');
        self::assertContains('honeytoken-retrieval', $v->detection->tags());
        self::assertContains('high-confidence', $v->detection->tags());

        // Without the cookie: same verdict/handle, but NO retrieval tag.
        $plain = $engine->classify(new RequestContext('GET', '/wp-admin/'), SiteProfile::empty());
        self::assertSame(self::GATE_ID, $plain->fakeHandle->ruleId);
        self::assertNotContains('honeytoken-retrieval', $plain->detection->tags());
    }

    // --- SAFETY / DETERMINISM ----------------------------------------------------------------

    public function test_authed_dashboard_bytes_clear_the_fingerprint_guard(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ([0, 1, 7, self::SEED, 12345] as $seed) {
            $r = $this->authedGet($seed);
            self::assertSame(200, $r->status, "seed {$seed}: cookie round-trips and the dashboard serves");
            self::assertSame([], $guard->scan($r->body), "seed {$seed}: dashboard body must be fingerprint-clean");
        }
    }

    public function test_same_request_and_cookie_serve_identical_bytes(): void
    {
        $em = $this->seededEmulator();
        $mint = $this->mint($em);
        $cookie = $this->cookieHeaderFrom($mint->headers['Set-Cookie']);
        $a = $em->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $cookie]));
        $b = $em->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $cookie]));
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, 'one deploy seed renders an identical dashboard every fetch');
    }

    public function test_no_unrendered_directive_or_example_literal_in_served_bytes(): void
    {
        $r = $this->authedGet();
        self::assertStringNotContainsString('{{', $r->body, 'no directive may survive unrendered');
        self::assertStringNotContainsString('example.com', $r->body);
    }

    public function test_planted_api_key_honeytoken_is_deterministic_and_persona_seeded(): void
    {
        // The planted per-user API-key cells are the guard-scanned FakeSecrets path, deterministic per
        // deploy seed and divergent across seeds.
        $a = $this->authedGet(self::SEED)->body;
        $b = $this->authedGet(self::SEED)->body;
        $c = $this->authedGet(self::SEED + 7)->body;

        self::assertSame($a, $b, 'same seed -> same planted tokens');
        self::assertNotSame($a, $c, 'a different deploy plants different tokens');

        // The first author's token is exactly FakeSecrets::apiKey for this seed/key (guard-scanned).
        $token = FakeSecrets::apiKey(self::SEED, 'wp_apppw#1');
        self::assertStringContainsString($token, $a, 'the planted cell is the guard-scanned FakeSecrets api key');
        self::assertSame(0, preg_match('/\b9\d{5}\b/', $token), 'the planted token carries no denylisted bare-CRS-rule-id run');
    }
}
