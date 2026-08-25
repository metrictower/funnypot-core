<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Honeytoken;
use PHPUnit\Framework\TestCase;

/**
 * DecoySession mints/gates a stateless mock-auth cookie over Honeytoken. The load-bearing
 * property under test: only a validly-signed `s=1` (authenticated) payload counts as
 * logged-in. A validly-signed `s=0` (pre-auth marker) must NEVER authenticate, even though
 * its signature checks out — s=0 and s=1 are domain-separated payload classes, not a
 * present/absent distinction.
 */
final class DecoySessionTest extends TestCase
{
    public function test_valid_s1_cookie_authenticates(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'phpMyAdmin=' . $value;

        self::assertTrue($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_valid_s0_cookie_never_authenticates(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->preAuthCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'phpMyAdmin=' . $value;

        self::assertFalse($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_null_header_is_false(): void
    {
        $session = new DecoySession('server-side-secret');

        self::assertFalse($session->isAuthenticated(null, 'phpMyAdmin'));
    }

    public function test_empty_header_is_false(): void
    {
        $session = new DecoySession('server-side-secret');

        self::assertFalse($session->isAuthenticated('', 'phpMyAdmin'));
    }

    public function test_garbage_value_is_false(): void
    {
        $session = new DecoySession('server-side-secret');

        self::assertFalse($session->isAuthenticated('phpMyAdmin=nonsense', 'phpMyAdmin'));
    }

    public function test_tampered_tag_is_false(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = rawurldecode($this->extractCookieValue($cookie, 'phpMyAdmin'));
        $sig = substr($value, strpos($value, '.') + 1);
        $tampered = rawurlencode('s=0.' . $sig);

        self::assertFalse($session->isAuthenticated('phpMyAdmin=' . $tampered, 'phpMyAdmin'));
    }

    public function test_different_cookie_name_present_is_false(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'pmaUser-1=' . $value;

        self::assertFalse($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_multi_cookie_header_extracts_the_right_one(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'pmaUser-1=x; phpMyAdmin=' . $value . '; pma_lang=en';

        self::assertTrue($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_cross_key_token_does_not_authenticate(): void
    {
        $signer = new DecoySession('key-a');
        $verifier = new DecoySession('key-b');
        $cookie = $signer->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'phpMyAdmin=' . $value;

        self::assertFalse($verifier->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_mint_cookie_payload_and_attributes(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');

        self::assertSame('s=1', (new Honeytoken('server-side-secret'))->verifiedPayload($value));
        self::assertStringContainsString('path=/phpmyadmin', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
    }

    public function test_pre_auth_cookie_payload_and_attributes(): void
    {
        $session = new DecoySession('server-side-secret');
        $cookie = $session->preAuthCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');

        self::assertSame('s=0', (new Honeytoken('server-side-secret'))->verifiedPayload($value));
        self::assertStringContainsString('path=/phpmyadmin', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
    }

    private function extractCookieValue(string $cookie, string $name): string
    {
        $value = substr($cookie, strlen($name . '='));

        return substr($value, 0, strpos($value, ';'));
    }
}
