<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware D-Link/HNAP SOAP Login credential oracle (attack rule 96). HNAP login is
 * two-phase: the "request" phase issues a challenge (the device returns Challenge/Cookie/PublicKey
 * and LoginResult OK BEFORE any credential is checked — a challenge is NOT authentication), and the
 * "login" phase submits the password hash. The rule dispatches on the ONE captured <Action> leaf via
 * `branch`. Pins the load-bearing safety invariants: NO success path (the login phase, every
 * non-request action, and the position-blind port all return <LoginResult>FAILED</LoginResult>, and
 * no token is ever granted), the posted password is never read (zero execution), nothing
 * attacker-controlled is reflected, and the challenge values are seed-derived and denylist-safe.
 *
 * NOTE ON PATHS: /HNAP1 has no route key, so a POST misses the exact store and reaches the attack tier.
 */
final class HnapLoginTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/HNAP1';
    private const ID = 'attack-hnap-login';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

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

    private function serve(string $method, ?string $body, int $seed = 0): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, self::PATH, '', [], $body), $seed);
    }

    /** A well-formed HNAP Login SOAP envelope for the given action + credentials. */
    private function envelope(string $action, string $user = 'Admin', string $pass = 'DEADBEEF'): string
    {
        return '<?xml version="1.0" encoding="utf-8"?>'
            . '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            . '<Login xmlns="http://purenetworks.com/HNAP1/">'
            . '<Action>' . $action . '</Action>'
            . '<Username>' . $user . '</Username>'
            . '<LoginPassword>' . $pass . '</LoginPassword>'
            . '<Captcha></Captcha>'
            . '</Login></soap:Body></soap:Envelope>';
    }

    private function assertWellFormedXml(string $xml, string $why): void
    {
        $prev = libxml_use_internal_errors(true);
        $doc = simplexml_load_string($xml);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        self::assertNotFalse($doc, $why . ' must be well-formed XML');
    }

    // --- compile / ordering -----------------------------------------------------------------

    public function test_rule_compiled_unique_branch_and_sorts_before_crs(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains(self::ID, $ids);
        self::assertSame(1, array_count_values($ids)[self::ID], 'rule id must be unique');

        $rule = $this->isolatedRule();
        self::assertSame('branch', $rule['behavior'] ?? null, 'must dispatch via branch');

        foreach (['attack-crs-sqli', 'attack-crs-xss'] as $crs) {
            if (in_array($crs, $ids, true)) {
                self::assertLessThan(
                    array_search($crs, $ids, true),
                    array_search(self::ID, $ids, true),
                    self::ID . ' must sort before ' . $crs
                );
            }
        }
    }

    // --- request-aware dispatch (exact status + Content-Type) --------------------------------

    public function test_login_phase_returns_bad_credentials(): void
    {
        $resp = $this->serve('POST', $this->envelope('login'));
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertSame('text/xml; charset=utf-8', $resp->headers['Content-Type'] ?? null);
        self::assertStringContainsString('<LoginResult>FAILED</LoginResult>', $resp->body);
        $this->assertWellFormedXml($resp->body, 'login-phase response');
    }

    public function test_request_phase_issues_a_challenge_not_authentication(): void
    {
        $resp = $this->serve('POST', $this->envelope('request'));
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertSame('text/xml; charset=utf-8', $resp->headers['Content-Type'] ?? null);
        // The challenge phase returns OK (challenge issued) plus the challenge material — but this is
        // NOT authentication: no session/token is granted here, and the actual login phase FAILS.
        self::assertStringContainsString('<LoginResult>OK</LoginResult>', $resp->body);
        self::assertStringContainsString('<Challenge>', $resp->body);
        self::assertStringContainsString('<Cookie>', $resp->body);
        self::assertStringContainsString('<PublicKey>', $resp->body);
        $this->assertWellFormedXml($resp->body, 'challenge response');
    }

    // --- NO success path (the load-bearing assertion) ---------------------------------------

    public function test_login_action_never_authenticates(): void
    {
        // The login phase (where credentials are actually submitted) never returns OK and never grants
        // a token — no matter the credentials. Isolated so a payload can't trip another attack rule.
        $emu = $this->isolated();
        foreach (['Admin', 'admin', 'root'] as $user) {
            foreach (['', 'password', 'DEADBEEFCAFE'] as $pass) {
                $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->envelope('login', $user, $pass)));
                self::assertNotNull($resp);
                self::assertStringContainsString('<LoginResult>FAILED</LoginResult>', $resp->body, "login must FAIL for {$user}/{$pass}");
                self::assertStringNotContainsString('<LoginResult>OK</LoginResult>', $resp->body, "login must never return OK for {$user}/{$pass}");
                self::assertStringNotContainsString('<PrivateLogin>', $resp->body, 'no token element');
                self::assertArrayNotHasKey('Set-Cookie', $resp->headers, 'no granted session cookie');
            }
        }
    }

    public function test_first_action_wins_a_planted_second_cannot_steer(): void
    {
        // Dispatch keys on the FIRST captured <Action> only: a login envelope with a decoy
        // <Action>request</Action> planted after it must still FAIL, never flip to the challenge.
        $body = '<Login><Action>login</Action><Username>a</Username><LoginPassword>x</LoginPassword><Action>request</Action></Login>';
        $resp = $this->serve('POST', $body);
        self::assertNotNull($resp);
        self::assertStringContainsString('<LoginResult>FAILED</LoginResult>', $resp->body);
        self::assertStringNotContainsString('<LoginResult>OK</LoginResult>', $resp->body, 'a planted second Action must not steer the dispatch');
    }

    // --- zero execution: the password is never read -----------------------------------------

    public function test_password_is_never_read_zero_execution(): void
    {
        // Login phase, same action + username, wildly different LoginPassword => byte-identical.
        $emu = $this->isolated();
        $post = function (string $pass) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->envelope('login', 'Admin', $pass)));
        };
        $a = $post('DEADBEEF');
        $b = $post('admin%27%20OR%201=1');
        $c = $post('../../etc/passwd');
        $d = $post('phar://a/evil.phar/x');
        self::assertNotNull($a);
        self::assertSame($a->body, $b->body, 'the posted password must not change the response');
        self::assertSame($a->body, $c->body);
        self::assertSame($a->body, $d->body, 'a URL password must not change the response (no egress)');
    }

    // --- reflect nothing --------------------------------------------------------------------

    public function test_nothing_attacker_controlled_is_reflected(): void
    {
        // Username/password are never echoed: the login FAILED body is a static literal, and the
        // challenge body only carries seed-derived fakes. A denied token planted in Username can't leak.
        $emu = $this->isolated();
        $guard = FingerprintGuard::fromPackage();
        foreach (['request', 'login'] as $action) {
            foreach (['900000', '<script>', 'Admin"'] as $user) {
                $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->envelope($action, $user, '900001')));
                self::assertNotNull($resp);
                self::assertStringNotContainsString($user, $resp->body, "username must never be reflected ({$action}): {$user}");
                self::assertStringNotContainsString('900001', $resp->body, 'password must never be reflected');
                self::assertSame([], $guard->scan($resp->body), "no denied token may reach the body ({$action})");
            }
        }
    }

    public function test_challenge_values_are_seed_derived_stable_and_distinct(): void
    {
        // The fake challenge material is per-seed stable (same seed => same value), differs across
        // seeds, and the three fields are independent — a coherent per-attacker device, never a
        // reused constant.
        $extract = function (object $resp, string $tag): string {
            self::assertSame(1, preg_match('#<' . $tag . '>([0-9a-f]{16})</' . $tag . '>#', $resp->body, $m), "{$tag} must be 16-hex");

            return $m[1];
        };
        $s1a = $this->serve('POST', $this->envelope('request'), 7);
        $s1b = $this->serve('POST', $this->envelope('request'), 7);
        $s2 = $this->serve('POST', $this->envelope('request'), 99);
        self::assertNotNull($s1a);
        self::assertNotNull($s2);
        $ch1 = $extract($s1a, 'Challenge');
        $ck1 = $extract($s1a, 'Cookie');
        $pk1 = $extract($s1a, 'PublicKey');
        self::assertSame($ch1, $extract($s1b, 'Challenge'), 'same seed => same challenge (stable)');
        self::assertNotSame($ch1, $extract($s2, 'Challenge'), 'different seed => different challenge');
        self::assertNotSame($ch1, $ck1, 'Challenge and Cookie are independent');
        self::assertNotSame($ch1, $pk1, 'Challenge and PublicKey are independent');
    }

    public function test_denied_token_sweep_across_seeds(): void
    {
        // The rendered challenge + base bodies must never carry a denied fingerprint token across a
        // wide seed sweep (a value-dependent hex island is what a bare-\b9\d{5}\b run would need).
        $emu = $this->isolated();
        $guard = FingerprintGuard::fromPackage();
        for ($i = 0; $i <= 500; $i++) {
            $seed = crc32((string) $i);
            foreach (['request', 'login'] as $action) {
                $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->envelope($action)), $seed);
                self::assertNotNull($resp, "seed#{$i} {$action}");
                self::assertSame([], $guard->scan($resp->body), "seed#{$i} {$action} leaks a denied token: " . $resp->body);
            }
        }
    }

    // --- method gate + non-dispatch cases ---------------------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', [], $this->envelope('login'))),
                "{$verb} must not dispatch"
            );
        }
    }

    public function test_post_without_action_does_not_dispatch(): void
    {
        // The <Action> capture-gate is required: a SOAP body with no <Action> misses => 404 territory,
        // never a synthetic 500.
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '<Login><Username>a</Username></Login>')));
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')));
    }

    // --- position-blind port degradation ----------------------------------------------------

    public function test_position_blind_port_serves_the_failed_base_not_the_challenge(): void
    {
        // On the position-blind port ($r === null) no branch case can evaluate, so the base (FAILED)
        // serves — never the OK challenge. The safe degradation for a credential oracle.
        $port = $this->emulator()->renderRule($this->isolatedRule(), [1 => 'request'], 0, null);
        self::assertNotNull($port);
        self::assertSame(200, $port->status);
        self::assertStringContainsString('<LoginResult>FAILED</LoginResult>', $port->body);
        self::assertStringNotContainsString('<LoginResult>OK</LoginResult>', $port->body, 'the challenge case must NOT fire on the port');
        self::assertSame([], FingerprintGuard::fromPackage()->scan($port->body));
    }

    // --- classify() end-to-end --------------------------------------------------------------

    private function fullEngine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'detect', null, 'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
    }

    public function test_classify_reaches_the_attack_tier(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', self::PATH, '', [], $this->envelope('login')),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    public function test_classify_store_shadowed_login_is_not_attack_class(): void
    {
        // Store-shadow guard: a store-keyed login POST that no rule owns via owns_path is answered
        // before the attack tier — NOT ATTACK_CLASS. /admin/login is one such still-unclaimed target
        // (wp-login.php no longer qualifies as of WP-Phase-2b: it is now owns_path-claimed).
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/admin/login', '', [], 'log=admin&pwd=x'),
            SiteProfile::empty()
        );
        self::assertNotSame(Verdict::ATTACK_CLASS, $verdict->classification);
    }
}
