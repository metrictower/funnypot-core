<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * A tamper-evident bait cookie. The honeypot plants a signed low-privilege cookie
 * (e.g. `r=user`); a client that replays it untouched is normal, but one that returns it
 * ALTERED (say `r=admin`) breaks the HMAC — a high-signal privilege-escalation attempt no
 * ordinary visitor produces. The key never leaves the server, so the signature is
 * unforgeable; the attacker can only strip or corrupt it.
 */
final class Honeytoken
{
    public function __construct(private string $key)
    {
    }

    /** A `Set-Cookie` value planting the signed bait. */
    public function cookie(string $name = 'sess', string $payload = 'r=user'): string
    {
        return $name . '=' . rawurlencode($payload . '.' . $this->sign($payload)) . '; path=/; HttpOnly';
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

    private function sign(string $payload): string
    {
        return substr(hash_hmac('sha256', $payload, $this->key), 0, 16);
    }
}
