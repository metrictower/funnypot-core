<?php

declare(strict_types=1);

namespace Funnypot\Support\Fake;

/**
 * Seeded fake-secret generator for the mock-auth panels: dead-but-syntactically-valid values
 * that authenticate to nothing anywhere. Every value is a pure function of (seed, key), and
 * per-(seed,key) unique — never a fixed world-known literal (e.g. the AWS docs example key) —
 * so an exfiltrated value can never correlate two deployments as both being funnypot.
 *
 * PHP 7.3-COMPATIBLE ON PURPOSE, mirroring FakePeople: plain static methods + arrays +
 * hash()/hexdec()/substr() only. Sub-hashes are tagged `|secret|`, distinct from FakePeople's
 * `|person|` tag, so a FakeSecrets value can never collide with a FakePeople one.
 *
 * Fingerprint-safety: every charset here is pure alnum (plus the bcrypt `$`-delimited cost
 * prefix), so each produced value is one contiguous word-character run far longer than 6 chars
 * (or, for bcryptHash, `$`-delimited runs of length 2 or 53). A bare `\b9\d{5}\b` match needs a
 * word-boundary on BOTH sides of an isolated 6-digit run; that can only happen at the two ends
 * of a run whose total length is exactly 6, which none of these are — so no generated value can
 * ever trip the denylist's bare-CRS-rule-id pattern, regardless of which digits land where.
 */
final class FakeSecrets
{
    private const UPPER_ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    private const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    private const HEX = '0123456789abcdef';

    private function __construct()
    {
    }

    /** A valid AWS access-key SHAPE ('AKIA' + 16 uppercase-alnum) that authenticates nowhere. */
    public static function apiKey(int $seed, string $key): string
    {
        return 'AKIA' . self::chars($seed, $key . '|apiKey', self::UPPER_ALNUM, 16);
    }

    /** A Stripe-test-key SHAPE. The `sk_test_` prefix (never `sk_live_`) signals non-live and
     *  keeps this out of secret-scanner "live key" quarantine paths. */
    public static function stripeKey(int $seed, string $key): string
    {
        return 'sk_test_' . self::chars($seed, $key . '|stripeKey', self::ALNUM, 24);
    }

    /** A 40-hex-char password-reset-token SHAPE. */
    public static function resetToken(int $seed, string $key): string
    {
        return self::chars($seed, $key . '|resetToken', self::HEX, 40);
    }

    /** A bcrypt-hash SHAPE ('$2y$10$' cost prefix + 53 chars), one-way and dead. */
    public static function bcryptHash(int $seed, string $key): string
    {
        return '$2y$10$' . self::chars($seed, $key . '|bcryptHash', self::ALNUM, 53);
    }

    /** A deterministic run of $length chars from $alphabet: each 32-char block is drawn from
     *  one sha256 (2 hex chars per output char), chained by block index for runs longer than
     *  one block yields, so any length can be produced from hash()/hexdec()/substr() alone. */
    private static function chars(int $seed, string $field, string $alphabet, int $length): string
    {
        $alphabetLen = strlen($alphabet);
        $out = '';
        $block = 0;
        while (strlen($out) < $length) {
            $h = self::hash($seed, $field . '|' . $block);
            for ($i = 0; $i < 64 && strlen($out) < $length; $i += 2) {
                $out .= $alphabet[hexdec(substr($h, $i, 2)) % $alphabetLen];
            }
            $block++;
        }

        return $out;
    }

    private static function hash(int $seed, string $field): string
    {
        return hash('sha256', $seed . '|secret|' . $field);
    }
}
