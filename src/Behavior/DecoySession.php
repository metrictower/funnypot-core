<?php

declare(strict_types=1);

namespace Funnypot\Behavior;

use Funnypot\Honeytoken;

/**
 * A stateless, self-verifying mock-auth decoy session. Two payload classes domain-separate
 * pre-auth from post-auth: `s=0` (visited the login page) and `s=1` (logged in). Only a
 * valid `s=1` counts as authenticated — a validly-signed `s=0` must NOT, even though its
 * HMAC checks out, because it is a different payload class, not a weaker version of `s=1`.
 */
final class DecoySession
{
    /** @var string */
    private $key;

    /** @var Honeytoken */
    private $token;

    public function __construct(string $key)
    {
        $this->key = $key;
        $this->token = new Honeytoken($key);
    }

    /** The Set-Cookie value for an authenticated session. */
    public function mintCookie(string $name, string $path): string
    {
        return $this->token->cookie($name, 's=1', $path);
    }

    /** The Set-Cookie value for the pre-auth marker (visited the login page, not logged in). */
    public function preAuthCookie(string $name, string $path): string
    {
        return $this->token->cookie($name, 's=0', $path);
    }

    /**
     * True iff the named cookie is present in the raw Cookie header, its tag verifies, AND
     * its payload is exactly `s=1`. Throw-free on any input.
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

        $payload = $this->token->verifiedPayload($rawValue);

        return $payload === 's=1';
    }
}
