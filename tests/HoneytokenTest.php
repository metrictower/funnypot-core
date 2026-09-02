<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Honeytoken;
use Funnypot\Core\Support\HoneytokenEnvelope;
use Funnypot\Core\Support\PersonaIdentity;
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
        // cookie() no longer defaults its name/payload (FP-0282: those fleet constants are dropped — see
        // the Reflection pin below); every caller names its own envelope.
        self::assertStringContainsString('path=/', $h->cookie('sess', 'r=user'));
        self::assertStringContainsString('HttpOnly', $h->cookie('sess', 'r=user'));
    }

    public function test_cookie_has_no_fleet_constant_name_or_payload_defaults(): void
    {
        // FP-0282: the 'sess'/'r=user' defaults were the fleet-constant bait envelope; they are gone so
        // no caller can silently plant the old constant. $path stays optional (a genuine convenience).
        $params = (new \ReflectionMethod(Honeytoken::class, 'cookie'))->getParameters();
        self::assertFalse($params[0]->isOptional(), 'cookie() name must be required (no fleet-constant default)');
        self::assertFalse($params[1]->isOptional(), 'cookie() payload must be required (no fleet-constant default)');
        self::assertTrue($params[2]->isOptional(), 'cookie() path stays optional');
    }

    // --- (c) bait(): the per-deploy seeded envelope (FP-0282) ---

    public function test_bait_is_deterministic_and_round_trips_across_seeds(): void
    {
        $h = new Honeytoken('server-side-secret');

        foreach (['', 'funnypot', 'fp-0276-sample-a', 'fp-0276-sample-b', 'm-17', 'm-42'] as $material) {
            $seed = PersonaIdentity::seedFromMaterial($material);

            // Within a deploy the bait is byte-identical every render (the within-deploy law).
            self::assertSame($h->bait($seed), $h->bait($seed), "bait must be stable for '{$material}'");

            // The browser sends the value back; it verifies, and reveals the seeded low-role payload.
            $name = HoneytokenEnvelope::name($seed);
            $value = $this->extractCookieValue($h->bait($seed), $name);
            self::assertSame('ok', $h->inspect($value), "bait must replay ok for '{$material}'");
            self::assertSame(HoneytokenEnvelope::payload($seed), $h->verifiedPayload($value), "payload for '{$material}'");

            // bait() is cookie() + envelope, with NO second signing path: the signed value part is
            // exactly what cookie(name, payload) produces.
            $viaCookie = $this->extractCookieValue($h->cookie($name, HoneytokenEnvelope::payload($seed), '/'), $name);
            self::assertSame($viaCookie, $value, "bait value must equal cookie()'s value for '{$material}'");
        }
    }

    public function test_bait_role_escalation_breaks_the_hmac(): void
    {
        $h = new Honeytoken('server-side-secret');
        $seed = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $name = HoneytokenEnvelope::name($seed);
        $value = $this->extractCookieValue($h->bait($seed), $name);

        $decoded = rawurldecode($value);
        $sig = substr($decoded, strpos($decoded, '.') + 1);
        // Raise the role word to admin: the payload no longer matches its signature.
        $tampered = rawurlencode('r=admin.' . $sig);
        self::assertSame('tampered', $h->inspect($tampered));
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
