<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Honeytoken;
use PHPUnit\Framework\TestCase;

/**
 * Honeytoken signs `payload.HMAC` for a tamper-evident bait cookie. Covers the existing
 * cookie()/inspect() behavior plus two additive pieces: a path-scoped cookie() (needed so a
 * decoy planted under e.g. /phpmyadmin doesn't leak to every path) and verifiedPayload(),
 * which returns the actual signed payload text (not just an ok/tampered classification) so a
 * caller can read e.g. a signed `s=0` vs `s=1`.
 */
final class HoneytokenTest extends TestCase
{
    // --- existing behavior, unchanged ---

    public function test_cookie_replay_ok_but_tamper_detected(): void
    {
        $h = new Honeytoken('server-side-secret');
        $cookie = $h->cookie('sess', 'r=user');

        $value = $this->extractCookieValue($cookie, 'sess');
        self::assertSame('ok', $h->inspect($value));
        self::assertSame('absent', $h->inspect(null));
        self::assertSame('absent', $h->inspect(''));

        $tampered = rawurlencode('r=admin.' . substr(rawurldecode($value), strpos(rawurldecode($value), '.') + 1));
        self::assertSame('tampered', $h->inspect($tampered));
    }

    // --- (a) path-scoped cookie() ---

    public function test_cookie_default_path_is_root(): void
    {
        $h = new Honeytoken('server-side-secret');

        // Lowercase `path=` matches PHP's setcookie() output (real PHP apps like phpMyAdmin) and
        // the rest of the codebase's cookie emitters — capital `Path=` would be a subtle tell.
        self::assertStringContainsString('path=/', $h->cookie());
        self::assertStringContainsString('HttpOnly', $h->cookie());
    }

    public function test_cookie_custom_path_is_scoped_and_not_root(): void
    {
        $h = new Honeytoken('server-side-secret');
        $cookie = $h->cookie('phpMyAdmin', 's=1', '/phpmyadmin');

        self::assertStringContainsString('path=/phpmyadmin', $cookie);
        self::assertStringNotContainsString('path=/;', $cookie);
    }

    // --- (b) verifiedPayload() ---

    public function test_verified_payload_returns_the_signed_payload(): void
    {
        $h = new Honeytoken('server-side-secret');
        $cookie = $h->cookie('n', 's=1');
        $value = $this->extractCookieValue($cookie, 'n');

        self::assertSame('s=1', $h->verifiedPayload($value));
    }

    public function test_verified_payload_null_on_tampered_value(): void
    {
        $h = new Honeytoken('server-side-secret');
        $cookie = $h->cookie('n', 's=1');
        $value = rawurldecode($this->extractCookieValue($cookie, 'n'));
        $sig = substr($value, strpos($value, '.') + 1);
        $tampered = rawurlencode('s=0.' . $sig);

        self::assertNull($h->verifiedPayload($tampered));
    }

    public function test_verified_payload_null_on_empty_string(): void
    {
        $h = new Honeytoken('server-side-secret');

        self::assertNull($h->verifiedPayload(''));
    }

    public function test_verified_payload_null_on_garbage_input(): void
    {
        $h = new Honeytoken('server-side-secret');

        self::assertNull($h->verifiedPayload('not-a-valid-token-no-dot'));
        self::assertNull($h->verifiedPayload('...'));
    }

    public function test_verified_payload_null_when_signed_under_a_different_key(): void
    {
        $signer = new Honeytoken('key-a');
        $verifier = new Honeytoken('key-b');
        $cookie = $signer->cookie('n', 's=1');
        $value = $this->extractCookieValue($cookie, 'n');

        self::assertNull($verifier->verifiedPayload($value));
    }

    private function extractCookieValue(string $cookie, string $name): string
    {
        $value = substr($cookie, strlen($name . '='));

        return substr($value, 0, strpos($value, ';'));
    }
}
