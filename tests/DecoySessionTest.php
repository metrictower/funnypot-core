<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\Honeytoken;
use PHPUnit\Framework\TestCase;

/**
 * DecoySession mints/gates a stateless mock-auth cookie over Honeytoken. The load-bearing property
 * under test: only a validly-signed value carrying THIS deploy's authenticated payload text counts as
 * logged-in. A validly-signed pre-auth marker, a legacy literal, and an authenticated token from a
 * DIFFERENT deploy seed must all fail — they are domain-separated payload classes / deploys, not a
 * present/absent distinction. The value token is deploy-seeded (FP-0296) so it is not a fleet-constant
 * fingerprint tell.
 */
final class DecoySessionTest extends TestCase
{
    private const KEY = 'server-side-secret';

    private const SEED_A = 101;

    private const SEED_B = 202;

    public function test_valid_authenticated_cookie_authenticates(): void
    {
        $session = new DecoySession(self::KEY);
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'phpMyAdmin=' . $value;

        self::assertTrue($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_valid_pre_auth_cookie_never_authenticates(): void
    {
        // A validly-signed pre-auth marker verifies cryptographically but is a DIFFERENT payload class.
        $session = new DecoySession(self::KEY);
        $cookie = $session->preAuthCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'phpMyAdmin=' . $value;

        self::assertFalse($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_legacy_literal_s1_is_rejected(): void
    {
        // The retired fleet-constant token `s=1` verifies under the key but is not this deploy's
        // authenticated text, so it fails the exact-class comparison (no dual-accept migration).
        $session = new DecoySession(self::KEY);
        $legacy = (new Honeytoken(self::KEY))->cookie('phpMyAdmin', 's=1', '/phpmyadmin');
        $value = $this->extractCookieValue($legacy, 'phpMyAdmin');

        self::assertFalse($session->isAuthenticated('phpMyAdmin=' . $value, 'phpMyAdmin'));
    }

    public function test_authenticated_cookie_from_another_deploy_seed_is_rejected(): void
    {
        // Same key, different deploy seed: the token verifies but its payload text is seed A's, not
        // seed B's, so a seed rotation clears the inert decoy login (fail-closed cross-seed).
        $signer = new DecoySession(self::KEY, self::SEED_A);
        $verifier = new DecoySession(self::KEY, self::SEED_B);
        // Precondition: the two seeds select different pairs (else the assertion would be vacuous).
        self::assertNotSame(
            DecoySessionPayloads::authenticated(self::SEED_A),
            DecoySessionPayloads::authenticated(self::SEED_B)
        );
        $value = $this->extractCookieValue($signer->mintCookie('phpMyAdmin', '/phpmyadmin'), 'phpMyAdmin');

        self::assertFalse($verifier->isAuthenticated('phpMyAdmin=' . $value, 'phpMyAdmin'));
        self::assertTrue($signer->isAuthenticated('phpMyAdmin=' . $value, 'phpMyAdmin'), 'seed A still accepts its own token');
    }

    public function test_omitted_and_null_seed_round_trip_as_seed_zero(): void
    {
        $implicit = new DecoySession(self::KEY);
        $explicitNull = new DecoySession(self::KEY, null);
        $explicitZero = new DecoySession(self::KEY, 0);

        $value = $this->extractCookieValue($implicit->mintCookie('phpMyAdmin', '/phpmyadmin'), 'phpMyAdmin');
        self::assertTrue($explicitNull->isAuthenticated('phpMyAdmin=' . $value, 'phpMyAdmin'));
        self::assertTrue($explicitZero->isAuthenticated('phpMyAdmin=' . $value, 'phpMyAdmin'));
        self::assertSame(
            DecoySessionPayloads::authenticated(0),
            (new Honeytoken(self::KEY))->verifiedPayload($value)
        );
    }

    public function test_null_header_is_false(): void
    {
        $session = new DecoySession(self::KEY);

        self::assertFalse($session->isAuthenticated(null, 'phpMyAdmin'));
    }

    public function test_empty_header_is_false(): void
    {
        $session = new DecoySession(self::KEY);

        self::assertFalse($session->isAuthenticated('', 'phpMyAdmin'));
    }

    public function test_garbage_value_is_false(): void
    {
        $session = new DecoySession(self::KEY);

        self::assertFalse($session->isAuthenticated('phpMyAdmin=nonsense', 'phpMyAdmin'));
    }

    public function test_tampered_tag_is_false(): void
    {
        $session = new DecoySession(self::KEY);
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = rawurldecode($this->extractCookieValue($cookie, 'phpMyAdmin'));
        $sig = substr($value, strpos($value, '.') + 1);
        // Keep a valid signature but swap the payload text: the tag no longer matches -> rejected.
        $tampered = rawurlencode(DecoySessionPayloads::preAuth(0) . '.' . $sig);

        self::assertFalse($session->isAuthenticated('phpMyAdmin=' . $tampered, 'phpMyAdmin'));
    }

    public function test_different_cookie_name_present_is_false(): void
    {
        $session = new DecoySession(self::KEY);
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');
        $header = 'pmaUser-1=' . $value;

        self::assertFalse($session->isAuthenticated($header, 'phpMyAdmin'));
    }

    public function test_multi_cookie_header_extracts_the_right_one(): void
    {
        $session = new DecoySession(self::KEY);
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
        $session = new DecoySession(self::KEY);
        $cookie = $session->mintCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');

        self::assertSame(DecoySessionPayloads::authenticated(0), (new Honeytoken(self::KEY))->verifiedPayload($value));
        self::assertStringContainsString('path=/phpmyadmin', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
    }

    public function test_pre_auth_cookie_payload_and_attributes(): void
    {
        $session = new DecoySession(self::KEY);
        $cookie = $session->preAuthCookie('phpMyAdmin', '/phpmyadmin');
        $value = $this->extractCookieValue($cookie, 'phpMyAdmin');

        self::assertSame(DecoySessionPayloads::preAuth(0), (new Honeytoken(self::KEY))->verifiedPayload($value));
        self::assertStringContainsString('path=/phpmyadmin', $cookie);
        self::assertStringContainsString('HttpOnly', $cookie);
    }

    public function test_is_authenticated_value_is_the_one_comparison(): void
    {
        // isAuthenticated() delegates to isAuthenticatedValue() on the extracted raw value.
        $session = new DecoySession(self::KEY, self::SEED_A);
        $value = $this->extractCookieValue($session->mintCookie('sess', '/'), 'sess');

        self::assertTrue($session->isAuthenticatedValue($value));
        self::assertFalse($session->isAuthenticatedValue('nonsense'));
        self::assertFalse($session->isAuthenticatedValue(''));
    }

    private function extractCookieValue(string $cookie, string $name): string
    {
        $value = substr($cookie, strlen($name . '='));

        return substr($value, 0, strpos($value, ';'));
    }
}
