<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\HoneytokenEnvelope;

/**
 * A tamper-evident bait cookie. The honeypot plants a signed low-privilege cookie carrying a seeded
 * low-role payload (e.g. `lvl=member`) whose name, payload vocabulary and attribute tail vary per deploy
 * (Support\HoneytokenEnvelope), so the envelope is not a fleet regex; a client that replays it untouched
 * is normal, but one that returns it ALTERED (say the role word raised to `admin`) breaks the HMAC — a
 * high-signal privilege-escalation attempt no ordinary visitor produces. The key never leaves the
 * server, so the signature is unforgeable; the attacker can only strip or corrupt it. The signature is
 * over the payload + key ONLY — the name and attributes never enter the HMAC.
 */
final class Honeytoken
{
    /** @var string */
    private $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * A `Set-Cookie` value planting the signed payload under an explicit name, scoped to the given path.
     * For the site-wide per-deploy bait cookie, use bait() (which seeds the whole envelope); this named
     * form is for callers that own a specific product-protocol cookie name (e.g. the decoy-session mint).
     */
    public function cookie(string $name, string $payload, string $path = '/'): string
    {
        return $name . '=' . rawurlencode($payload . '.' . $this->sign($payload)) . '; path=' . $path . '; HttpOnly';
    }

    /**
     * The site-wide bait `Set-Cookie` for this deploy: a seeded envelope (name + `key=role` low-role
     * payload + attribute tail, all from HoneytokenEnvelope) wrapped around the SAME signed
     * `payload.16hex` value cookie() produces. inspect()/verifiedPayload() need no change — the value
     * shape is identical; only the envelope varies. A seed rotation invalidates old bait cookies, which
     * reads as an ordinary server-side session reset (inspect() returns `absent` for the old name).
     */
    public function bait(int $deploySeed, string $path = '/'): string
    {
        $payload = HoneytokenEnvelope::payload($deploySeed);

        return HoneytokenEnvelope::name($deploySeed)
            . '=' . rawurlencode($payload . '.' . $this->sign($payload))
            . HoneytokenEnvelope::attributes($deploySeed, $path);
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
     * actual signed payload text so a caller can distinguish two validly-signed payload classes
     * (e.g. the decoy session's pre-auth vs authenticated text). Throw-free on any input.
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
