<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Behavior\DecoySession;

/**
 * Detect that a request presents a valid, minted decoy-session cookie — i.e. the client walked the
 * mock-auth login (phpMyAdmin "breached DB" or any future decoy panel) and is now pulling loot from
 * behind it. Like OastProbe this is a DETECT-ONLY signal: a valid authenticated payload can only exist
 * if we minted it (the HMAC key never leaves the server, so it is unforgeable), so its presence is
 * high-confidence evidence that the attacker committed budget to the trap.
 *
 * Name-agnostic on purpose: it inspects EVERY cookie value in the Cookie header, not one fixed cookie
 * name, so a future decoy panel that mints under a different name is covered with no change here. The
 * result label lives only in this detector's source (and the fold's tags) — never in a served byte —
 * so it cannot fingerprint the honeypot, and the response is byte-identical whether or not it fires.
 * Side-effect-free and throw-free: pure string work over the Cookie header, no DNS, no fetch, no I/O.
 */
final class DecoySessionProbe
{
    /**
     * True iff any cookie in the request's Cookie header carries a value that verifies (under $key) to
     * THIS deploy's authenticated decoy-session payload. A validly-signed pre-auth marker is a
     * DIFFERENT payload class and must NOT count; so does an authenticated value from another deploy
     * seed. An empty key disables the probe (no decoy session configured ⇒ nothing to verify against).
     * The deploy seed must be the SAME snapshot the mint path used, so the engine passes its stored
     * value here rather than re-reading mutable Config.
     */
    public static function authenticated(RequestContext $r, string $key, ?int $deploySeed = null): bool
    {
        if ($key === '') {
            return false;
        }

        $header = self::cookieHeader($r);
        if ($header === '') {
            return false;
        }

        $session = new DecoySession($key, $deploySeed);
        foreach (explode(';', $header) as $pair) {
            $pair = trim($pair);
            $eq = strpos($pair, '=');
            if ($eq === false) {
                continue;
            }
            if ($session->isAuthenticatedValue(substr($pair, $eq + 1))) {
                return true;
            }
        }

        return false;
    }

    /** The raw Cookie header, matched case-insensitively (HTTP header names are case-insensitive). */
    private static function cookieHeader(RequestContext $r): string
    {
        foreach ($r->headers as $name => $value) {
            if (strcasecmp((string) $name, 'Cookie') === 0) {
                return (string) $value;
            }
        }

        return '';
    }
}
