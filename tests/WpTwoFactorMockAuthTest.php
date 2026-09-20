<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0492 — the optional fake 2FA interstitial folded into the mock-auth funnel. The two-step flow is
 * driven through in-test FIXTURE rules (two_factor ON), mirroring DecoySessionBehaviorTest, because the
 * SHIPPED templates keep two_factor OFF (proven separately against the compiled artifact below, so
 * WpAdminMockAuthTest stays byte-identical). Pins:
 *  - two-step mint: a plausible login POST sets a 2fa-PENDING cookie and 302s to the challenge page;
 *  - the challenge form renders ONLY for a verified pending cookie;
 *  - accept-any-code: any code with the pending cookie mints the IDENTICAL inert authenticated cookie
 *    the one-step mint sets, and 302s to the authed panel;
 *  - the paramount safety invariant: a 2fa-pending cookie NEVER authenticates the gate;
 *  - CONDITION A: the verify POST (same path+method as the mint) mints AUTHENTICATED, never re-mints a
 *    pending cookie — no re-mint loop (the verify is folded into the mint handler, no second rule);
 *  - dormancy: key off OR two_factor off ⇒ byte-identical to the one-step funnel;
 *  - the challenge body is fingerprint-clean and reflects no submitted value.
 */
final class WpTwoFactorMockAuthTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private const SEED = 484348449122915112;

    private const LOGIN_BASE = '<html>LOGIN_BASE_STUB</html>';

    private const CHALLENGE_BASE = '<html>CHALLENGE_BASE_STUB</html>';

    /** @return array<string,mixed> the mint rule with the 2FA opt-in on. */
    private function mintRule(): array
    {
        return [
            'id' => 'decoy-mint-2fa-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^POST$'],
                ['in' => 'path', 'regex' => '(?:^|/)wp-login\.php/*$', 'ci' => true],
                [
                    'in' => 'body',
                    'regex' => '^(?:(?=(?:.*&)?log=(?P<user>[^&]{0,64})))?(?:(?=(?:.*&)?pwd=(?P<pass>[^&]{0,64})))?(?:(?=(?:.*&)?code=(?P<code>[^&]{0,64})))?',
                    'capture' => true,
                    'ci' => false,
                ],
            ],
            'response' => ['headers' => [], 'body' => self::LOGIN_BASE],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'mint',
                'cookie_name' => 'sess',
                'cookie_path' => '/',
                'redirect' => '/wp-admin/',
                'two_factor' => true,
                'two_factor_redirect' => '/wp-login.php?action=2fa',
            ],
        ];
    }

    /** @return array<string,mixed> the mint rule with the 2FA opt-in OFF (legacy one-step). */
    private function mintRuleNoTwoFactor(): array
    {
        $rule = $this->mintRule();
        $rule['id'] = 'decoy-mint-legacy-fixture';
        $rule['decoy-session']['two_factor'] = false;
        unset($rule['decoy-session']['two_factor_redirect']);

        return $rule;
    }

    /** @return array<string,mixed> the challenge (GET code-form) rule. */
    private function challengeRule(): array
    {
        return [
            'id' => 'decoy-challenge-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 200,
            'match' => [
                ['in' => 'method', 'regex' => '^(?:GET|HEAD)$'],
                ['in' => 'path', 'regex' => '(?:^|/)wp-login\.php/*$', 'ci' => true],
                ['in' => 'query', 'regex' => '(?:^|&)action=2fa(?:&|$)', 'ci' => true],
            ],
            'response' => ['headers' => [], 'body' => self::CHALLENGE_BASE],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'challenge',
                'panel' => 'wordpress',
                'cookie_name' => 'sess',
                'cookie_path' => '/',
                'form_action' => '/wp-login.php?action=2fa',
            ],
        ];
    }

    /** @return array<string,mixed> the authed gate rule (unchanged, WordPress panel). */
    private function gateRule(): array
    {
        return [
            'id' => 'decoy-gate-fixture',
            'severity' => 'info',
            'tags' => [],
            'status' => 302,
            'match' => [
                ['in' => 'method', 'regex' => '^(?:GET|HEAD)$'],
                ['in' => 'path', 'regex' => '^/wp-admin/*$', 'ci' => true],
            ],
            'response' => ['headers' => ['Location' => '/wp-login.php'], 'body' => ''],
            'behavior' => 'decoy-session',
            'decoy-session' => [
                'mode' => 'gate',
                'panel' => 'wordpress',
                'cookie_name' => 'sess',
                'cookie_path' => '/',
                'domain' => 'example.test',
            ],
        ];
    }

    /** @param array<int,array<string,mixed>> $rules */
    private function emulator(array $rules, ?string $key = self::KEY): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator($rules, [], null, null, [], null, $key);
    }

    /** The name=value a browser sends back, parsed out of a full Set-Cookie string. */
    private function cookieHeaderFrom(string $setCookie): string
    {
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    private function rawValue(string $nameValue): string
    {
        $eq = strpos($nameValue, '=');

        return $eq === false ? $nameValue : substr($nameValue, $eq + 1);
    }

    // --- two-step mint --------------------------------------------------------------------------

    public function test_login_post_with_two_factor_on_sets_a_pending_cookie_and_302s_to_challenge(): void
    {
        $em = $this->emulator([$this->mintRule()]);
        $r = $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));

        self::assertNotNull($r);
        self::assertSame(302, $r->status, 'a plausible login mints step 1');
        self::assertSame('/wp-login.php?action=2fa', $r->headers['Location'], 'step 1 302s to the challenge page');

        $value = $this->rawValue($this->cookieHeaderFrom($r->headers['Set-Cookie']));
        $session = new DecoySession(self::KEY, 0);
        self::assertTrue($session->isTwoFactorPendingValue($value), 'step 1 sets the 2fa-pending cookie');
        self::assertFalse($session->isAuthenticatedValue($value), 'step 1 must NOT set an authenticated cookie');
    }

    // --- challenge gated by the pending cookie -------------------------------------------------

    public function test_challenge_renders_the_code_form_only_with_a_pending_cookie(): void
    {
        $em = $this->emulator([$this->challengeRule()]);
        $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintPendingCookie('sess', '/'));

        $r = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa', ['Cookie' => $pending]));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('Authentication Code', $r->body, 'the code-entry form renders');
        self::assertStringContainsString('name="code"', $r->body);
        self::assertStringContainsString('action="/wp-login.php?action=2fa"', $r->body, 'the form posts back to the verify action');
        self::assertStringNotContainsString(self::CHALLENGE_BASE, $r->body);
    }

    public function test_challenge_declines_to_base_without_a_valid_pending_cookie(): void
    {
        $em = $this->emulator([$this->challengeRule()]);
        $auth = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintCookie('sess', '/'));
        $pre = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->preAuthCookie('sess', '/'));

        $cases = [
            'no cookie'        => null,
            'authenticated'    => $auth,   // wrong class
            'pre-auth'         => $pre,    // wrong class
            'garbage'          => 'sess=nonsense-not-signed',
        ];
        foreach ($cases as $label => $cookie) {
            $headers = $cookie === null ? [] : ['Cookie' => $cookie];
            $r = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa', $headers));
            self::assertNotNull($r, $label);
            self::assertSame(self::CHALLENGE_BASE, $r->body, "{$label}: the code form must not render cold");
            self::assertStringNotContainsString('Authentication Code', $r->body, $label);
        }
    }

    // --- accept-any-code -> authenticated (CONDITION A: no re-mint loop) -----------------------

    public function test_verify_accepts_any_code_and_mints_the_identical_authenticated_cookie(): void
    {
        $em = $this->emulator([$this->challengeRule(), $this->mintRule(), $this->gateRule()]);
        $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintPendingCookie('sess', '/'));

        foreach (['000000', 'whatever', '123456', 'not-a-number'] as $code) {
            // The verify POST hits the SAME path+method as the initial mint, carrying the pending cookie.
            $r = $em->emulate(new RequestContext('POST', '/wp-login.php', 'action=2fa', ['Cookie' => $pending], 'code=' . $code));
            self::assertNotNull($r, $code);
            self::assertSame(302, $r->status, "[{$code}] any code advances");
            self::assertSame('/wp-admin/', $r->headers['Location'], "[{$code}] verify 302s to the authed panel, NOT back to the challenge");

            $value = $this->rawValue($this->cookieHeaderFrom($r->headers['Set-Cookie']));
            $session = new DecoySession(self::KEY, 0);
            self::assertTrue($session->isAuthenticatedValue($value), "[{$code}] verify mints the authenticated cookie");
            self::assertFalse($session->isTwoFactorPendingValue($value), "[{$code}] verify must NOT re-mint a pending cookie (no loop)");
            // The minted authenticated cookie is byte-identical to the one-step mint's cookie.
            self::assertSame(DecoySessionPayloads::authenticated(0), (new Honeytoken(self::KEY))->verifiedPayload($value), "[{$code}] identical inert authenticated payload");
        }
    }

    public function test_verify_with_pending_cookie_but_no_code_declines(): void
    {
        // Accept-ANY-code still requires a code to be present; an empty submission is not a verify.
        $em = $this->emulator([$this->challengeRule(), $this->mintRule(), $this->gateRule()]);
        $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintPendingCookie('sess', '/'));

        $r = $em->emulate(new RequestContext('POST', '/wp-login.php', 'action=2fa', ['Cookie' => $pending], 'code='));
        self::assertNotNull($r);
        self::assertSame(self::LOGIN_BASE, $r->body, 'an empty code declines to the base login page');
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
    }

    // --- paramount: the pending cookie never authenticates the gate ----------------------------

    public function test_pending_cookie_never_renders_the_authed_dashboard(): void
    {
        $em = $this->emulator([$this->gateRule()]);
        $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintPendingCookie('sess', '/'));

        $r = $em->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $pending]));
        self::assertNotNull($r);
        self::assertSame(302, $r->status, 'a pending cookie falls through to the gate decline (login redirect)');
        self::assertSame('/wp-login.php', $r->headers['Location']);
        self::assertSame('', $r->body);
        self::assertStringNotContainsString('At a Glance', $r->body);
        self::assertStringNotContainsString('wp-list-table', $r->body);
    }

    // --- full end-to-end walk through one emulator --------------------------------------------

    public function test_full_two_step_flow_end_to_end(): void
    {
        $em = $this->emulator([$this->challengeRule(), $this->mintRule(), $this->gateRule()]);

        // 1) login POST -> pending cookie + 302 to challenge
        $step1 = $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));
        self::assertNotNull($step1);
        self::assertSame('/wp-login.php?action=2fa', $step1->headers['Location']);
        $pending = $this->cookieHeaderFrom($step1->headers['Set-Cookie']);

        // 2) GET challenge with the pending cookie -> the code form
        $step2 = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa', ['Cookie' => $pending]));
        self::assertNotNull($step2);
        self::assertStringContainsString('Authentication Code', $step2->body);

        // 3) POST any code with the pending cookie -> authenticated cookie + 302 to /wp-admin/
        $step3 = $em->emulate(new RequestContext('POST', '/wp-login.php', 'action=2fa', ['Cookie' => $pending], 'code=424242'));
        self::assertNotNull($step3);
        self::assertSame('/wp-admin/', $step3->headers['Location']);
        $authed = $this->cookieHeaderFrom($step3->headers['Set-Cookie']);

        // 4) GET /wp-admin/ with the authenticated cookie -> the dashboard
        $step4 = $em->emulate(new RequestContext('GET', '/wp-admin/', '', ['Cookie' => $authed]));
        self::assertNotNull($step4);
        self::assertSame(200, $step4->status);
        self::assertStringContainsString('At a Glance', $step4->body);
        self::assertStringContainsString('wp-list-table', $step4->body);
    }

    // --- dormancy: two independent off-switches ------------------------------------------------

    public function test_key_off_is_byte_identical_one_step_decline(): void
    {
        $em = $this->emulator([$this->challengeRule(), $this->mintRule(), $this->gateRule()], null);

        $post = $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));
        self::assertNotNull($post);
        self::assertSame(self::LOGIN_BASE, $post->body, 'key off: the login POST declines to the base page');
        self::assertArrayNotHasKey('Set-Cookie', $post->headers);

        $challenge = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa'));
        self::assertNotNull($challenge);
        self::assertSame(self::CHALLENGE_BASE, $challenge->body, 'key off: the challenge declines to its base page');
    }

    public function test_two_factor_off_is_the_legacy_one_step_mint(): void
    {
        $em = $this->emulator([$this->mintRuleNoTwoFactor()]);
        $r = $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('/wp-admin/', $r->headers['Location'], '2FA off: mint straight to the authed panel');
        $value = $this->rawValue($this->cookieHeaderFrom($r->headers['Set-Cookie']));
        $session = new DecoySession(self::KEY, 0);
        self::assertTrue($session->isAuthenticatedValue($value), '2FA off: the authenticated cookie is minted directly');
        self::assertFalse($session->isTwoFactorPendingValue($value), '2FA off: no pending cookie');
    }

    // --- the SHIPPED compiled artifact keeps two_factor OFF -----------------------------------

    public function test_shipped_wp_login_is_still_the_one_step_mint(): void
    {
        // The shipped 97-wp-login.yaml ships two_factor OFF, so the compiled mint is the legacy one-step
        // login (this is what keeps WpAdminMockAuthTest byte-identical).
        $em = TemplateAttackEmulator::fromFile(self::COMPILED, [], self::SEED, self::KEY);
        $r = $em->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));

        self::assertNotNull($r);
        self::assertSame(302, $r->status);
        self::assertSame('/wp-admin/', $r->headers['Location'], 'shipped mint 302s straight to /wp-admin/ (2FA off)');
        self::assertStringNotContainsString('action=2fa', $r->headers['Location']);
    }

    public function test_shipped_challenge_rule_is_dormant_without_a_pending_cookie(): void
    {
        // With two_factor off no pending cookie is ever minted, so the shipped challenge rule always
        // declines to its base login page — never the code form.
        $em = TemplateAttackEmulator::fromFile(self::COMPILED, [], self::SEED, self::KEY);
        $r = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa'));

        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringNotContainsString('Authentication Code', $r->body, 'no code form without a pending cookie');
        self::assertStringContainsString('Register For This Site', $r->body, 'declines to the login page base');
    }

    // --- fingerprint-safety + no reflection ---------------------------------------------------

    public function test_challenge_body_is_fingerprint_clean_across_seeds(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ([0, 1, 7, self::SEED, 12345] as $seed) {
            $em = new TemplateAttackEmulator([$this->challengeRule()], [], null, null, [], $seed, self::KEY);
            $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, $seed))->mintPendingCookie('sess', '/'));
            $r = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa', ['Cookie' => $pending]), $seed);
            self::assertNotNull($r, "seed {$seed}");
            self::assertSame(200, $r->status, "seed {$seed}: the code form serves");
            self::assertSame([], $guard->scan($r->body), "seed {$seed}: challenge body must be fingerprint-clean");
            self::assertStringNotContainsString('{{', $r->body, 'no directive survives unrendered');
        }
    }

    public function test_challenge_reflects_no_submitted_code(): void
    {
        // A crafted code posted at the challenge action is never echoed into the served bytes.
        $em = $this->emulator([$this->challengeRule()]);
        $pending = $this->cookieHeaderFrom((new DecoySession(self::KEY, 0))->mintPendingCookie('sess', '/'));
        $r = $em->emulate(new RequestContext('GET', '/wp-login.php', 'action=2fa&code=' . rawurlencode('<script>x'), ['Cookie' => $pending]));

        self::assertNotNull($r);
        self::assertStringNotContainsString('<script>', $r->body, 'no submitted value is reflected');
    }
}
