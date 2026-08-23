<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\FakeHandle;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Response\Style;
use Funnypot\SiteProfile;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Template\TemplateAttackEmulator;
use Funnypot\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware WordPress wp-login.php credential emulator (attack rule 97, WP-Phase-2b).
 * Drives the compiled attack rules against a live RequestContext, so it pins the zero-reflection
 * and never-authenticate safety invariants and the owns_path override that lets a POST reach this
 * rule ahead of route 50's static GET page.
 *
 * owns_path IS LOAD-BEARING here (unlike a rule with no real-store collision): the REAL compiled
 * corpus resources/compiled/nuclei-index.full.php — what PhpArrayStore::fromPackage() loads in prod —
 * has a live exact-store bundle keyed EXACTLY `POST /wp-login.php` (nuclei template
 * `white-label-cms`, CVE-2022-0422): a benign-but-still-wrong 200 text/html body carrying
 * `wlcms-login-wrapper` and a literal `alert(/XSS/);` marker. Without owns_path, classify() would
 * resolve a POST here to that corpus bundle instead of this oracle; see
 * test_classify_overrides_the_live_white_label_cms_bundle and
 * test_served_response_is_the_oracle_never_the_white_label_cms_bundle below, which drive a full
 * Honeypot over the REAL corpus (not the compiled attack rules alone) to pin the override.
 */
final class WpLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const ID = 'attack-wp-login';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /**
     * A full Honeypot over the REAL compiled corpus (nuclei-index.full.php — what
     * PhpArrayStore::fromPackage() loads in prod), not the small test fixture. This is the only way
     * to reproduce the live `POST /wp-login.php` = white-label-cms collision owns_path overrides;
     * mirrors KibanaLoginOracleTest::fullEngine(), with mode='respond' (+ a permissive gate) when the
     * test also needs the actual served bytes, not just the verdict.
     */
    private function fullEngine(bool $respondMode = false): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            $respondMode ? 'respond' : 'detect',
            $respondMode ? static function (RequestContext $r): bool { return true; } : null,
            'matched-only', null, 'coherent', Style::MINIMAL,
            'high', 65536, 0, 0, true /* attackEmulation */
        );

        return new Honeypot($store, $config);
    }

    public function test_rule_compiled_and_owns_the_bare_path(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains('attack-wp-login', $ids);

        self::assertTrue(
            $this->emulator()->ownsPath('/wp-login.php'),
            'the compiled wp-login rule must claim /wp-login.php so classify() overrides the static route'
        );
    }

    // --- REGRESSION: owns_path overrides a LIVE corpus bundle at this exact path --------------------

    /**
     * The real compiled corpus (nuclei-index.full.php) has a bundle keyed EXACTLY `POST
     * /wp-login.php` — nuclei template `white-label-cms` (CVE-2022-0422), a 200 text/html body.
     * Without owns_path, classify() would resolve this request to a ROUTE handle onto that bundle
     * (Verdict::SCANNER_PROBE), not this oracle. This pins that classify() instead returns the
     * ATTACK_CLASS verdict with THIS rule's handle, so a future owns_path removal or corpus/index
     * rebuild that drops the override can't silently regress into serving the wrong panel's page.
     */
    public function test_classify_overrides_the_live_white_label_cms_bundle(): void
    {
        $verdict = $this->fullEngine()->classify(
            new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=x'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertNotNull($verdict->fakeHandle);
        self::assertSame(
            FakeHandle::KIND_ATTACK,
            $verdict->fakeHandle->kind,
            'must be the attack-tier handle, not a route handle onto the white-label-cms bundle'
        );
        self::assertSame(self::ID, $verdict->fakeHandle->ruleId);
        self::assertContains(self::ID, $verdict->detection->templateIds());
    }

    /**
     * The actual served bytes (via the full respond() facade over the REAL corpus) must be this
     * oracle's wp-login `login_error` page — never the white-label-cms bundle's body (its
     * `wlcms-login-wrapper` marker and literal `alert(/XSS/);` string).
     */
    public function test_served_response_is_the_oracle_never_the_white_label_cms_bundle(): void
    {
        $engine = $this->fullEngine(true);

        $r = $engine->respond(new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=x'));
        self::assertNotNull($r);
        self::assertStringContainsString('login_error', $r->body);
        self::assertStringNotContainsString(
            'wlcms-login-wrapper',
            $r->body,
            'must not be the white-label-cms bundle body'
        );
        self::assertStringNotContainsString(
            'alert(/XSS/);',
            $r->body,
            'must not be the white-label-cms bundle\'s XSS marker'
        );
    }

    public function test_bad_credentials_are_a_200_oracle_naming_the_fixed_persona_user(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=hunter2'));
        self::assertNotNull($r);

        self::assertSame(200, $r->status); // bad creds are never 4xx/302 — a non-200 is a tell
        self::assertSame('text/html; charset=UTF-8', $r->headers['Content-Type']);
        self::assertSame('Wed, 11 Jan 1984 05:00:00 GMT', $r->headers['Expires']);
        self::assertSame('no-cache, must-revalidate, max-age=0', $r->headers['Cache-Control']);
        self::assertArrayNotHasKey('Location', $r->headers);

        self::assertStringContainsString('login_error', $r->body);
        self::assertStringContainsString('admin', $r->body);
        self::assertSame(['attack-wp-login'], $r->satisfies->templateIds());
    }

    // --- SAFETY: zero-reflection — the submitted username is captured only to gate the match ------

    public function test_submitted_username_is_never_reflected(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=root&pwd=hunter2'));
        self::assertNotNull($r);
        self::assertStringNotContainsString('root', $r->body);
    }

    public function test_crafted_username_never_surfaces_in_the_served_body(): void
    {
        $r = $this->emulator()->emulate(new RequestContext(
            'POST',
            '/wp-login.php',
            '',
            [],
            'log=' . rawurlencode('<script>alert(1)</script>') . '&pwd=x'
        ));
        self::assertNotNull($r);
        self::assertStringNotContainsString('<script>alert(1)</script>', $r->body);
        self::assertStringNotContainsString('script', $r->body);
    }

    // --- SAFETY: never authenticates — no success path, no auth cookie -----------------------------

    public function test_no_authenticated_session_cookie_is_ever_set(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('POST', '/wp-login.php', '', [], 'log=admin&pwd=hunter2'));
        self::assertNotNull($r);
        self::assertArrayHasKey('Set-Cookie', $r->headers);
        self::assertDoesNotMatchRegularExpression('/wordpress_logged_in|wordpress_sec/i', $r->headers['Set-Cookie']);
        // The inert pre-auth cookie a real server also sets is fine; it grants nothing.
        self::assertStringContainsString('wordpress_test_cookie', $r->headers['Set-Cookie']);
    }

    // --- POST-gated: a GET must decline so the static route can serve ------------------------------

    public function test_get_does_not_return_the_oracle(): void
    {
        $r = $this->emulator()->emulate(new RequestContext('GET', '/wp-login.php', '', [], null));
        if ($r !== null) {
            self::assertNotSame(['attack-wp-login'], $r->satisfies->templateIds());
        } else {
            self::assertNull($r);
        }
    }
}
