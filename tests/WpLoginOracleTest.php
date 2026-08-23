<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware WordPress wp-login.php credential emulator (attack rule 97, WP-Phase-2b).
 * Drives the compiled attack rules against a live RequestContext, so it pins the zero-reflection
 * and never-authenticate safety invariants and the owns_path override that lets a POST reach this
 * rule ahead of route 50's static GET page.
 */
final class WpLoginOracleTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
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
