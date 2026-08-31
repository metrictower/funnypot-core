<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * A tamper-evident bait cookie. The honeypot plants a signed low-privilege cookie
 * (e.g. `r=user`); a client that replays it untouched is normal, but one that returns it
 * ALTERED (say `r=admin`) breaks the HMAC — a high-signal privilege-escalation attempt no
 * ordinary visitor produces. The key never leaves the server, so the signature is
 * unforgeable; the attacker can only strip or corrupt it.
 */
final class Honeytoken
{
    /** @var string */
    private $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /** A `Set-Cookie` value planting the signed bait, scoped to the given path. */
    public function cookie(string $name = 'sess', string $payload = 'r=user', string $path = '/'): string
    {
        return $name . '=' . rawurlencode($payload . '.' . $this->sign($payload)) . '; path=' . $path . '; HttpOnly';
    }

    /**
     * Classify an incoming cookie value:
     *   absent   — not present (ordinary first visit)
     *   ok       — replayed untouched (normal)
     *   tampered — signature does not match the payload → someone edited it (HIGH signal)
     */
    public function inspect(?string $raw): string
    {
        if ($raw === null || $raw === '') {
            return 'absent';
        }
        $value = rawurldecode($raw);
        $dot = strrpos($value, '.');
        if ($dot === false) {
            return 'tampered';
        }
        $payload = substr($value, 0, $dot);
        $sig = substr($value, $dot + 1);

        return hash_equals($this->sign($payload), $sig) ? 'ok' : 'tampered';
    }

    /**
     * The verified payload from a raw cookie value, or null if it's missing, malformed, or
     * tampered. Unlike inspect() (which only classifies absent|ok|tampered), this returns the
     * actual signed payload text so a caller can distinguish e.g. a signed `s=0` from `s=1`.
     * Throw-free on any input.
     */
    public function verifiedPayload(string $raw): ?string
    {
        if ($raw === '') {
            return null;
        }
        $value = rawurldecode($raw);
        $dot = strrpos($value, '.');
        if ($dot === false) {
            return null;
        }
        $payload = substr($value, 0, $dot);
        $sig = substr($value, $dot + 1);

        return hash_equals($this->sign($payload), $sig) ? $payload : null;
    }

    /**
     * A base64url-encoded, HMAC-signed reference token for the FP-0239 prompt-injection self-beacon:
     * `base64url( ref . '.' . sign(ref) )`. The ref is a SERVER-derived render-seed reference (never
     * attacker input), so the token cannot reflect attacker bytes; a beacon hit decodes back to which
     * deploy seeded the page (the app follow-up verifies it with hash_equals against the same key).
     * Reuses the exact sign() HMAC — no new crypto scheme.
     */
    public function beaconToken(string $ref): string
    {
        $raw = $ref . '.' . $this->sign($ref);

        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    private function sign(string $payload): string
    {
        return substr(hash_hmac('sha256', $payload, $this->key), 0, 16);
    }
}
