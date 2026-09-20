<?php

declare(strict_types=1);

namespace Funnypot\Core\Behavior;

use Funnypot\Core\Honeytoken;
use Funnypot\Core\Support\BoundedInspection;

/**
 * A stateless, self-verifying mock-auth decoy session. THREE payload classes domain-separate the login
 * funnel: a selected pre-auth text (visited the login page), a selected 2fa-pending text (password
 * accepted, verification code not yet entered), and a selected authenticated text (logged in). The
 * three texts are ONE deploy-seeded triple from DecoySessionPayloads, so the wire token is not a
 * fleet-constant fingerprint tell. Only the selected authenticated text counts as logged in — a
 * validly-signed pre-auth OR 2fa-pending value must NOT, even though its HMAC checks out, because it is
 * a different payload class, not a weaker version of the authenticated one. Likewise the 2fa-pending
 * class is strictly separate from pre-auth: `isTwoFactorPending()` accepts only the pending text.
 *
 * The session grants nothing: it is an inert decoy the honeypot mints to bait post-login probing. A
 * legacy literal token, or an authenticated token from another deploy seed, verifies cryptographically
 * under a reused key but fails the exact-class comparison — a seed rotation clears only an inert decoy
 * login, the same visible effect as an ordinary server-side session reset.
 */
final class DecoySession
{
    /** @var string */
    private $key;

    /** @var Honeytoken */
    private $token;

    /** @var int the deploy identity seed selecting the payload pair; null maps to seed 0 */
    private $deploySeed;

    public function __construct(string $key, ?int $deploySeed = null)
    {
        $this->key = $key;
        $this->token = new Honeytoken($key);
        $this->deploySeed = $deploySeed ?? 0;
    }

    /** The Set-Cookie value for an authenticated session. */
    public function mintCookie(string $name, string $path): string
    {
        return $this->token->cookie($name, DecoySessionPayloads::authenticated($this->deploySeed), $path);
    }

    /** The Set-Cookie value for the pre-auth marker (visited the login page, not logged in). */
    public function preAuthCookie(string $name, string $path): string
    {
        return $this->token->cookie($name, DecoySessionPayloads::preAuth($this->deploySeed), $path);
    }

    /** The Set-Cookie value for the 2fa-pending marker (password accepted, code not yet entered). */
    public function mintPendingCookie(string $name, string $path): string
    {
        return $this->token->cookie($name, DecoySessionPayloads::twoFactorPending($this->deploySeed), $path);
    }

    /**
     * True iff the named cookie is present in the raw Cookie header, its tag verifies, AND its payload
     * is exactly this deploy's authenticated text. Throw-free on any input.
     */
    public function isAuthenticated(?string $cookieHeader, string $name): bool
    {
        if ($cookieHeader === null || $cookieHeader === '') {
            return false;
        }

        if (strlen($name) > BoundedInspection::COOKIE_NAME_BYTES) {
            return false;
        }
        $pairs = BoundedInspection::cookiePairs($cookieHeader);
        if ($pairs === null) {
            return false;
        }
        foreach ($pairs as $pair) {
            if ($pair[0] === $name) {
                return $this->isAuthenticatedValue($pair[1]);
            }
        }

        return false;
    }

    /**
     * The one authoritative authentication test: a raw cookie value verifies (under this key) to
     * exactly this deploy's authenticated payload text. A validly-signed pre-auth value, a legacy
     * literal, and an authenticated value from another deploy seed all fail here. Throw-free on any
     * input.
     */
    public function isAuthenticatedValue(string $rawValue): bool
    {
        if (strlen($rawValue) > BoundedInspection::COOKIE_VALUE_BYTES) {
            return false;
        }

        return $this->token->verifiedPayload($rawValue) === DecoySessionPayloads::authenticated($this->deploySeed);
    }

    /**
     * True iff the named cookie is present in the raw Cookie header, its tag verifies, AND its payload
     * is exactly this deploy's 2fa-pending text. A pre-auth or authenticated value fails here — the
     * pending class is strictly separate, not a weaker or stronger form of either. Throw-free on any
     * input; mirrors isAuthenticated()'s bounded cookie walk.
     */
    public function isTwoFactorPending(?string $cookieHeader, string $name): bool
    {
        if ($cookieHeader === null || $cookieHeader === '') {
            return false;
        }

        if (strlen($name) > BoundedInspection::COOKIE_NAME_BYTES) {
            return false;
        }
        $pairs = BoundedInspection::cookiePairs($cookieHeader);
        if ($pairs === null) {
            return false;
        }
        foreach ($pairs as $pair) {
            if ($pair[0] === $name) {
                return $this->isTwoFactorPendingValue($pair[1]);
            }
        }

        return false;
    }

    /**
     * The one authoritative 2fa-pending test: a raw cookie value verifies (under this key) to exactly
     * this deploy's 2fa-pending payload text. A pre-auth value, an authenticated value, a legacy
     * literal, and a pending value from another deploy seed all fail here. Throw-free on any input.
     */
    public function isTwoFactorPendingValue(string $rawValue): bool
    {
        if (strlen($rawValue) > BoundedInspection::COOKIE_VALUE_BYTES) {
            return false;
        }

        return $this->token->verifiedPayload($rawValue) === DecoySessionPayloads::twoFactorPending($this->deploySeed);
    }
}
