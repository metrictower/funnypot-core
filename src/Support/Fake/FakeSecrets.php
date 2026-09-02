<?php

declare(strict_types=1);

namespace Funnypot\Core\Support\Fake;

use Funnypot\Core\Support\SubSeed;

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
 * Fingerprint-safety: most shapes here are pure alnum (`apiKey`'s base32, `stripeKey`'s `_`-joined
 * alnum, the hex `resetToken`/`flag` body), each a single contiguous word-character run far longer
 * than 6 chars — a bare `\b9\d{5}\b` match needs word boundaries on BOTH sides of an isolated
 * 6-digit run, which can only sit at the two ends of a run whose total length is exactly 6, so
 * none of those can ever trip the denylist's bare-CRS-rule-id pattern. `bcryptHash` is the one
 * exception: its legal `./` alphabet inserts NON-word chars into the 53-char tail, so an interior
 * `\b` can isolate a 6-digit run. That value is therefore composed and then guarded — any draw
 * that trips `hitsDeniedDigits` is re-rolled (round-tagged, terminating in ~1-2 rounds almost
 * surely) BEFORE return, exactly as PersonaIdentity's boundary-prone generators do. Every public
 * generator runs the same guard loop for uniformity; for the always-contiguous shapes round 0
 * always passes, so their bytes are unchanged.
 *
 * Stripe-prefix policy (see also PersonaIdentity::cloud stripe.secretKey): this browsing-surface
 * generator deliberately emits `sk_test_` (never `sk_live_`) — an interactively-browsed mock-auth
 * panel row need not defeat a secret-scanner's live-key rule, and `sk_test_` keeps a casually
 * shared screenshot/loot low-stakes. The leaked-config BAIT templates use PersonaIdentity's
 * load-bearing `sk_live_` instead (its `expect:` markers pin it so a scanner's live-key rule
 * bites). The two prefixes are intentionally NOT unified.
 */
final class FakeSecrets
{
    private const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const BCRYPT64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    private const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    private const HEX = '0123456789abcdef';

    private function __construct()
    {
    }

    /** A valid AWS access-key SHAPE ('AKIA' + 16 chars of base32 [A-Z2-7]) that authenticates nowhere.
     *  Base32 (no 0/1/8/9) matches a real access-key-id encoding — the digits a real key never carries
     *  were a checkable tell — and mirrors PersonaIdentity::awsAccessKeyId. */
    public static function apiKey(int $seed, string $key): string
    {
        for ($round = 0; ; $round++) {
            $value = 'AKIA' . self::chars($seed, self::field($key, 'apiKey', $round), self::BASE32, 16);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /** A Stripe-test-key SHAPE. The `sk_test_` prefix (never `sk_live_`) signals non-live and
     *  keeps this out of secret-scanner "live key" quarantine paths (see the class policy note). */
    public static function stripeKey(int $seed, string $key): string
    {
        for ($round = 0; ; $round++) {
            $value = 'sk_test_' . self::chars($seed, self::field($key, 'stripeKey', $round), self::ALNUM, 24);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /** A 40-hex-char password-reset-token SHAPE. */
    public static function resetToken(int $seed, string $key): string
    {
        for ($round = 0; ; $round++) {
            $value = self::chars($seed, self::field($key, 'resetToken', $round), self::HEX, 40);
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * A legal bcrypt-hash SHAPE — the `$2y$10$` cost header + a 53-char tail (22-char salt + 31-char
     * hash) in bcrypt's own `./A-Za-z0-9` base64 alphabet, one-way and dead. Two shape rules a real
     * `$2y$` hash obeys that a naive alnum draw does not: (1) the alphabet includes `.` and `/`, and
     * (2) the 22-char salt encodes 128 bits into 132 base64 bit-positions, so the 22nd (last) salt
     * char carries only 2 significant bits — only `.`, `O`, `e`, `u` (alphabet indices 0/16/32/48)
     * can legally appear there. Both are enforced here, mirroring PersonaIdentity::bcryptHash. The
     * salt-pad char is drawn per (seed, key) (not `$seed & 3`) so a table of hashes doesn't share one
     * pad char. The `./` are non-word chars that can isolate a 6-digit run, so the WHOLE composed
     * value is guarded by the re-roll loop (round-tagged re-derive on a denied-digit hit).
     */
    public static function bcryptHash(int $seed, string $key): string
    {
        $pad = ['.', 'O', 'e', 'u'];
        for ($round = 0; ; $round++) {
            $blob = self::chars($seed, self::field($key, 'bcryptHash', $round), self::BCRYPT64, 53);
            $blob[21] = $pad[hexdec(substr(self::hash($seed, self::field($key, 'bcryptSaltPad', $round)), 0, 2)) % 4];
            $value = '$2y$10$' . $blob;
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
    }

    /**
     * A CTF-sentinel flag SHAPE — `FLAG.{<40 lowercase-hex>}.GALF` — an obviously-inert honeytoken
     * meant to be auto-submitted by flag-hunting agents (it authenticates/validates nowhere). The
     * inner 40-hex run is drawn per-(seed,key) via the same chars() path as resetToken, so it is
     * per-deploy stable and never a world-known literal.
     *
     * Fingerprint-safety: the `FLAG`/`GALF` wrappers are pure letters and the `.`/`{`/`}` delimiters
     * are non-word chars, so the only word-boundaries sit at the two brace edges of the length-40 hex
     * run — there is no `\b` INSIDE the run. A bare `\b9\d{5}\b` match needs word-boundaries on both
     * sides of an isolated 6-digit run, which can only sit at the two ends of a run of total length
     * exactly 6; the 40-run is far longer, so no value can ever trip the denylist's bare-CRS-rule-id
     * pattern regardless of which digits land where. The re-roll guard below therefore never engages
     * for this shape (round 0 always passes) and its bytes are unchanged.
     */
    public static function flag(int $seed, string $key): string
    {
        for ($round = 0; ; $round++) {
            $value = 'FLAG.{' . self::chars($seed, self::field($key, 'flag', $round), self::HEX, 40) . '}.GALF';
            if (!self::hitsDeniedDigits($value)) {
                return $value;
            }
        }
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

    /**
     * The sub-hash field key for a generator's round. Round 0 is `$key . '|' . $tag` — byte-identical
     * to the pre-guard material, so a value that never trips the denylist is unchanged — and each
     * later round appends `|r<round>` to re-derive fresh material on a re-roll (mirrors the round tag
     * PersonaIdentity's boundary-prone generators use).
     */
    private static function field(string $key, string $tag, int $round): string
    {
        return $round === 0 ? $key . '|' . $tag : $key . '|' . $tag . '|r' . $round;
    }

    /**
     * True if a composed secret carries the fingerprint gate's denied bare-6-digit token
     * (`\b9\d{5}\b`, a bare CRS rule id — see resources/fingerprint-denylist.php). A served body that
     * trips it is classified as canned and, on the mock-auth panel, fails closed to the login page,
     * so any generator whose alphabet can isolate a 6-digit run re-derives until clean. Mirrors
     * PersonaIdentity::hitsDeniedDigits.
     */
    private static function hitsDeniedDigits(string $value): bool
    {
        return SubSeed::hitsDeniedDigits($value);
    }

    private static function hash(int $seed, string $field): string
    {
        return hash('sha256', $seed . '|secret|' . $field);
    }
}
