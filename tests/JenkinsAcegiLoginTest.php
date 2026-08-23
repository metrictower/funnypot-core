<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Response\Style;
use Funnypot\SiteProfile;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use Funnypot\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware Jenkins Acegi/Spring-Security form-login credential oracle (attack rule 95). A
 * brute POST to /j_acegi_security_check is answered with the authentic Spring Security failure
 * redirect: 302 to the fixed loginError page. Pins the load-bearing safety invariants: NO success
 * path (a 302 to /loginError, never a 200/authenticated redirect, never a session-grant cookie), the
 * posted password is never read (zero execution), nothing attacker-controlled is reflected, and the
 * Location is a static literal (no open redirect, no CR/LF).
 *
 * Content-Type: a real modern Jenkins (Jetty + Spring Security) sends the failure redirect with an
 * empty body and NO Content-Type. Because the rule authors X-Content-Type-Options, renderRule does
 * not inject its text/plain default, so the served 302 carries no Content-Type — byte-faithful.
 *
 * NOTE ON PATHS: /j_acegi_security_check has no route key, so a POST misses the exact store and
 * reaches the attack tier.
 */
final class JenkinsAcegiLoginTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/j_acegi_security_check';
    private const ID = 'attack-jenkins-acegi-login';

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

    // --- request-aware dispatch (exact status + headers) ------------------------------------

    public function test_genuine_login_post_serves_the_failure_redirect(): void
    {
        $resp = $this->serve('POST', 'j_username=admin&j_password=hunter2&from=%2F&Submit=Sign+in');
        self::assertNotNull($resp);
        self::assertSame(302, $resp->status);
        self::assertSame('/loginError', $resp->headers['Location'] ?? null);
        self::assertSame('nosniff', $resp->headers['X-Content-Type-Options'] ?? null);
        self::assertSame('', $resp->body, 'the failure redirect has an empty body');
        // A real modern Jenkins empty 302 carries no Content-Type; the engine must not inject one.
        self::assertArrayNotHasKey('Content-Type', $resp->headers, 'the empty 302 carries no Content-Type');
    }

    // --- NO success path (the load-bearing assertion) ---------------------------------------

    public function test_no_success_path_ever(): void
    {
        // Every credential POST fails: 302 to /loginError, never a 200 or a redirect to an
        // authenticated landing page, and never a session-grant cookie.
        $emu = $this->isolated();
        foreach (['j_username=admin&j_password=admin', 'j_username=root&j_password=', 'j_username=jenkins&j_password=jenkins'] as $body) {
            $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], $body));
            self::assertNotNull($resp, $body);
            self::assertSame(302, $resp->status, $body);
            self::assertSame('/loginError', $resp->headers['Location'] ?? null, "must redirect to the failure URL only: {$body}");
            self::assertArrayNotHasKey('Set-Cookie', $resp->headers, "no granted session cookie: {$body}");
        }
    }

    // --- zero execution: the password is never read -----------------------------------------

    public function test_password_is_never_read_zero_execution(): void
    {
        // Same username, wildly different passwords (including injection strings) => byte-identical
        // response. Isolated so a payload in j_password can't trip another attack rule.
        $emu = $this->isolated();
        $post = function (string $pass) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], 'j_username=admin&j_password=' . $pass));
        };
        $a = $post('hunter2');
        $b = $post('admin%27%20OR%20%271%27%3D%271');
        $c = $post('..%2F..%2Fetc%2Fpasswd');
        $d = $post('phar%3A%2F%2Fa%2Fevil.phar%2Fx');
        self::assertNotNull($a);
        self::assertSame('', $a->body);
        self::assertSame($a->body, $b->body);
        self::assertSame($a->body, $c->body);
        self::assertSame($a->body, $d->body, 'a URL password must not change the response (no egress)');
        // Headers are identical too — nothing attacker-controlled rides through.
        self::assertSame($a->headers, $b->headers);
    }

    // --- reflect nothing --------------------------------------------------------------------

    public function test_nothing_attacker_controlled_is_reflected(): void
    {
        // The username gates the match only; the redirect Location is a static literal. A hostile
        // j_username can neither reach the body (empty) nor the Location header.
        $emu = $this->isolated();
        $guard = FingerprintGuard::fromPackage();
        foreach (['900000', '<script>', 'admin"', 'evil.example/%0d%0aInjected'] as $user) {
            $resp = $emu->emulate(new RequestContext('POST', self::PATH, '', [], 'j_username=' . rawurlencode($user) . '&j_password=x'));
            self::assertNotNull($resp, $user);
            self::assertSame('/loginError', $resp->headers['Location'] ?? null, "Location must stay the static literal: {$user}");
            self::assertStringNotContainsString($user, $resp->body, $user);
            self::assertSame([], $guard->scan($resp->body));
            self::assertSame([], $guard->scan($resp->headers['Location'] ?? ''));
        }
    }

    // --- method gate ------------------------------------------------------------------------

    public function test_non_post_verbs_do_not_dispatch(): void
    {
        $emu = $this->isolated();
        foreach (['GET', 'HEAD', 'PUT'] as $verb) {
            self::assertNull(
                $emu->emulate(new RequestContext($verb, self::PATH, '', [], 'j_username=admin&j_password=x')),
                "{$verb} must not dispatch"
            );
        }
    }

    public function test_post_without_username_field_does_not_dispatch(): void
    {
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], 'nothing=here')));
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')));
    }

    // --- position-blind port degradation ----------------------------------------------------

    public function test_position_blind_port_serves_the_failure_redirect(): void
    {
        $port = $this->emulator()->renderRule($this->isolatedRule(), [1 => 'admin'], 0, null);
        self::assertNotNull($port);
        self::assertSame(302, $port->status);
        self::assertSame('/loginError', $port->headers['Location'] ?? null);
        self::assertSame('', $port->body);
        self::assertArrayNotHasKey('Content-Type', $port->headers);
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
            new RequestContext('POST', self::PATH, '', [], 'j_username=admin&j_password=hunter2'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    public function test_classify_store_shadowed_login_is_not_attack_class(): void
    {
        // Store-shadow guard: the legacy /j_security_check IS an exact-store key, answered before the
        // attack tier — NOT ATTACK_CLASS. Documents the deferred (store-shadowed) sibling.
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/j_security_check', '', [], 'j_username=admin&j_password=x'),
            SiteProfile::empty()
        );
        self::assertNotSame(Verdict::ATTACK_CLASS, $verdict->classification);
    }
}
