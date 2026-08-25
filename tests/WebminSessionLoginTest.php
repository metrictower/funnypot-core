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
 * The request-aware Webmin/miniserv session_login.cgi credential oracle (attack rule 94). A
 * brute/cred-stuffing POST to /session_login.cgi is answered with the authentic "Login failed"
 * login page — a canned bad-credentials response that never authenticates. Pins the load-bearing
 * safety invariants: NO success path (no sid session cookie, no dashboard redirect), the posted
 * password is never read beyond the capture-gate (zero execution), the username is never reflected
 * (reflect-nothing, so a numeric username can't surface as a denied token), and the rule is gated to
 * POST so any other verb degrades to a plain 404.
 *
 * NOTE ON PATHS: /session_login.cgi has no route key, so a POST misses the exact store and reaches
 * the attack tier. Adversarial-payload assertions (a password carrying an SQLi/LFI/XSS string) run
 * against the rule in ISOLATION, because the broad SQLi/LFI/XSS archetypes sort before priority 94
 * and would otherwise claim such a request first — the same isolation the Ignition test uses.
 */
final class WebminSessionLoginTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/session_login.cgi';
    private const ID = 'attack-webmin-session-login';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** The compiled Webmin rule alone, so an adversarial credential can't trip an earlier broad rule. */
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

    private function serve(string $method, ?string $body): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, self::PATH, '', [], $body));
    }

    // --- compile / ordering -----------------------------------------------------------------

    public function test_rule_compiled_unique_and_sorts_before_crs(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains(self::ID, $ids);
        self::assertSame(1, array_count_values($ids)[self::ID], 'rule id must be unique');

        // Priority 94 sorts strictly before the broad CRS archetypes (priority 950+), so a specific
        // login oracle is reached before the generic CRS SQL-error rule.
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

    public function test_genuine_login_post_serves_the_failed_login_page(): void
    {
        // A plain brute (benign credentials) reaches the oracle and gets the authentic failed-login
        // page: 200 text/html, the "Login failed" banner, and the miniserv Server banner in lockstep
        // with route 370.
        $resp = $this->serve('POST', 'user=admin&pass=hunter2&page=/');
        self::assertNotNull($resp);
        self::assertSame(200, $resp->status);
        self::assertSame('text/html; charset=utf-8', $resp->headers['Content-Type'] ?? null);
        self::assertSame('MiniServ/2.111', $resp->headers['Server'] ?? null, 'Server banner lockstep with route 370');
        self::assertStringContainsString('Login failed', $resp->body);
        self::assertStringContainsString('action="/session_login.cgi"', $resp->body);
    }

    // --- NO success path (the load-bearing assertion) ---------------------------------------

    public function test_no_success_path_ever(): void
    {
        // Every credential POST is bad credentials: 200 (not a 302 to a dashboard), no Location, and
        // the cookie is miniserv's static `testing` probe — never a granted `sid=` session token.
        $emu = $this->isolated();
        foreach (['user=admin&pass=admin', 'user=root&pass=toor', 'user=Admin&pass='] as $body) {
            $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $body));
            self::assertNotNull($resp, $body);
            self::assertSame(200, $resp->status, "must never redirect to an authenticated page: {$body}");
            self::assertArrayNotHasKey('Location', $resp->headers, "no authenticated redirect: {$body}");
            $cookie = $resp->headers['Set-Cookie'] ?? '';
            self::assertStringNotContainsStringIgnoringCase('sid=', $cookie, "no granted session cookie: {$body}");
            self::assertStringContainsString('Login failed', $resp->body, $body);
        }
    }

    // --- zero execution: the password is never read beyond the gate --------------------------

    public function test_password_is_never_read_zero_execution(): void
    {
        // Same username, wildly different passwords (including injection strings) => byte-identical
        // response. The password is never read: no file, no include, no eval, no egress. Isolated so a
        // traversal/SQLi payload in `pass` can't trip another attack rule.
        $emu = $this->isolated();
        $post = function (string $pass) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], 'user=admin&pass=' . $pass));
        };
        $a = $post('hunter2');
        $b = $post('admin%27%20OR%20%271%27%3D%271');
        $c = $post('..%2F..%2Fetc%2Fpasswd');
        $d = $post('phar%3A%2F%2Fa%2Fevil.phar%2Fx');
        self::assertNotNull($a);
        self::assertSame($a->body, $b->body, 'an SQLi password must not change the response');
        self::assertSame($a->body, $c->body, 'a traversal password must not change the response');
        self::assertSame($a->body, $d->body, 'a phar password must not change the response (no egress)');
    }

    // --- reflect nothing: the username never reaches the body --------------------------------

    public function test_username_is_never_reflected(): void
    {
        // The `user` field is a match-gate only; it is never echoed. A numeric username can never
        // surface as a bare CRS-rule-id token, and an injection username can never break the HTML.
        $emu = $this->isolated();
        $guard = FingerprintGuard::fromPackage();
        foreach (['900000', '<script>alert(1)</script>', 'admin"', "admin' OR '1'='1"] as $user) {
            $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], 'user=' . rawurlencode($user) . '&pass=x'));
            self::assertNotNull($resp, $user);
            self::assertStringNotContainsString($user, $resp->body, "username must never be reflected: {$user}");
            self::assertSame([], $guard->scan($resp->body), "no denied token may reach the body: {$user}");
        }
    }

    // --- method gate ------------------------------------------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        // Gated to POST: any other verb misses (no route here) => the caller's plain 404, never a
        // synthetic response. Isolated so the assertion is about this rule's own method gate.
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT', 'DELETE'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', [], 'user=admin&pass=x')),
                "{$verb} must not dispatch"
            );
        }
    }

    public function test_post_without_user_field_does_not_dispatch(): void
    {
        // The `user` capture-gate is required: a POST with no user field misses => 404 territory,
        // never a synthetic 500 (only-upgrade-a-404).
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], 'nothing=here')));
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')));
    }

    // --- position-blind port degradation ----------------------------------------------------

    public function test_position_blind_port_serves_the_bad_credentials_base(): void
    {
        // On the position-blind port (renderRule with $r === null) the base response serves — the
        // safe degradation. Still the failed-login page, still no crash, scan clean.
        $port = $this->emulator()->renderRule($this->isolatedRule(), [1 => 'zzcapturedzz'], 0, null);
        self::assertNotNull($port);
        self::assertSame(200, $port->status);
        self::assertStringContainsString('Login failed', $port->body);
        self::assertStringNotContainsString('zzcapturedzz', $port->body, 'the captured user must not be reflected on the port');
        self::assertSame([], FingerprintGuard::fromPackage()->scan($port->body));
    }

    // --- classify() end-to-end (path misses the store, reaches the attack tier) --------------

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
            new RequestContext('POST', self::PATH, '', [], 'user=admin&pass=hunter2'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    public function test_classify_store_shadowed_login_is_not_attack_class(): void
    {
        // Store-shadow guard: POST /admin/login is an exact-store key that no rule owns via
        // owns_path, so it is answered before the attack tier is ever reached — NOT an ATTACK_CLASS
        // verdict (wp-login.php no longer qualifies as of WP-Phase-2b: it is now owns_path-claimed).
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/admin/login', '', [], 'log=admin&pwd=x'),
            SiteProfile::empty()
        );
        self::assertNotSame(Verdict::ATTACK_CLASS, $verdict->classification);
    }
}
