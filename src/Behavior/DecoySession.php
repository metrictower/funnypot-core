<?php

declare(strict_types=1);

namespace Funnypot\Core\Behavior;

use Funnypot\Core\Honeytoken;

/**
 * A stateless, self-verifying mock-auth decoy session. Two payload classes domain-separate pre-auth
 * from post-auth: a selected pre-auth text (visited the login page) and a selected authenticated text
 * (logged in). The two texts are ONE deploy-seeded pair from DecoySessionPayloads, so the wire token
 * is not a fleet-constant fingerprint tell. Only the selected authenticated text counts as logged in —
 * a validly-signed pre-auth value must NOT, even though its HMAC checks out, because it is a different
 * payload class, not a weaker version of the authenticated one.
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

    /**
     * True iff the named cookie is present in the raw Cookie header, its tag verifies, AND its payload
     * is exactly this deploy's authenticated text. Throw-free on any input.
     */
    public function isAuthenticated(?string $cookieHeader, string $name): bool
    {
        if ($cookieHeader === null || $cookieHeader === '') {
            return false;
        }

        $rawValue = null;
        foreach (explode(';', $cookieHeader) as $pair) {
            $pair = trim($pair);
            $eq = strpos($pair, '=');
            if ($eq === false) {
                continue;
            }
            if (substr($pair, 0, $eq) === $name) {
                $rawValue = substr($pair, $eq + 1);
                break;
            }
        }

        if ($rawValue === null) {
            return false;
        }

        return $this->isAuthenticatedValue($rawValue);
    }

    /**
     * The one authoritative authentication test: a raw cookie value verifies (under this key) to
     * exactly this deploy's authenticated payload text. A validly-signed pre-auth value, a legacy
     * literal, and an authenticated value from another deploy seed all fail here. Throw-free on any
     * input.
     */
    public function isAuthenticatedValue(string $rawValue): bool
    {
        return $this->token->verifiedPayload($rawValue) === DecoySessionPayloads::authenticated($this->deploySeed);
    }
}
