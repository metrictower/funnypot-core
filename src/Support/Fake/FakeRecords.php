<?php

declare(strict_types=1);

namespace Funnypot\Support\Fake;

/**
 * Seeded fake-table-row generator for the mock-auth panels, built on FakePeople + FakeSecrets.
 * Each method returns a list of rows (each row a list of string cells), and every row is a pure
 * function of (seed, key, rowIndex) — same inputs always produce the same row, so a table
 * renders identically every fetch for one deployment while a different seed (deploy) or key
 * (panel) diverges. Per-row identity is drawn via FakePeople::person($seed, "$key#$i") — the row
 * key format used across every method here — so the same row index always maps to the same
 * underlying person (sessions folds $domain into that key too: a session belongs to an account
 * on that deploy's domain, even though no cell shows the domain directly).
 *
 * PHP 7.3-COMPATIBLE ON PURPOSE, mirroring FakePeople: plain static methods + arrays +
 * hash()/hexdec()/substr() only. Sub-hashes are tagged `|record|`, distinct from FakePeople's
 * `|person|` and FakeSecrets' `|secret|` tags.
 *
 * Fingerprint-safety: numeric cells (id, order_id, amount) are kept short enough that they can
 * never form the isolated 6-digit run the denylist's `\b9\d{5}\b` bare-CRS-rule-id pattern
 * matches. ids stay exactly 5 digits (10000-99999): one digit short of the pattern's 6, so no
 * value of any digit can ever trip it. Amounts format as `{0-9999}.{00-99}`: the '.' splits the
 * cell into two runs (max 4 digits, exactly 2 digits) each too short to match, regardless of
 * which digits land where.
 */
final class FakeRecords
{
    private const STATUSES = ['pending', 'paid', 'shipped', 'refunded', 'cancelled'];

    private function __construct()
    {
    }

    /** Rows [id, username, email, created_at]. */
    public static function users(int $seed, string $domain, string $key, int $n): array
    {
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $rowKey = $key . '#' . $i;
            $person = FakePeople::person($seed, $rowKey);
            $rows[] = [
                self::id($seed, $rowKey . '|id'),
                $person['userName'],
                FakePeople::email($person, $domain),
                FakePeople::date($seed, $rowKey . '|created'),
            ];
        }

        return $rows;
    }

    /** Rows [email, reset_token, requested_at, expires_at]. */
    public static function passwordResets(int $seed, string $domain, string $key, int $n): array
    {
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $rowKey = $key . '#' . $i;
            $person = FakePeople::person($seed, $rowKey);
            $rows[] = [
                FakePeople::email($person, $domain),
                FakeSecrets::resetToken($seed, $rowKey),
                FakePeople::date($seed, $rowKey . '|requested'),
                FakePeople::date($seed, $rowKey . '|expires'),
            ];
        }

        return $rows;
    }

    /** Rows [id, owner_name, api_key, created_at, last_used_at]. The secret column alternates
     *  shape (AWS-style vs Stripe-test-style) per row, both dead, both from FakeSecrets. */
    public static function apiKeys(int $seed, string $key, int $n): array
    {
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $rowKey = $key . '#' . $i;
            $person = FakePeople::person($seed, $rowKey);
            $useStripeShape = self::index($seed, $rowKey . '|kind', 2) === 1;
            $secret = $useStripeShape
                ? FakeSecrets::stripeKey($seed, $rowKey)
                : FakeSecrets::apiKey($seed, $rowKey);
            $rows[] = [
                self::id($seed, $rowKey . '|id'),
                $person['full'],
                $secret,
                FakePeople::date($seed, $rowKey . '|created'),
                FakePeople::date($seed, $rowKey . '|lastUsed'),
            ];
        }

        return $rows;
    }

    /** Rows [id, username, ip, last_activity]. $domain scopes the underlying person draw (a
     *  session belongs to an account on that deploy's domain) even though no cell shows it. */
    public static function sessions(int $seed, string $domain, string $key, int $n): array
    {
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $rowKey = $key . '#' . $i . '@' . $domain;
            $person = FakePeople::person($seed, $rowKey);
            $rows[] = [
                self::id($seed, $rowKey . '|id'),
                $person['userName'],
                FakePeople::ipv4($seed, $rowKey),
                FakePeople::date($seed, $rowKey . '|activity'),
            ];
        }

        return $rows;
    }

    /** Rows [order_id, customer, amount, status, created_at]. */
    public static function orders(int $seed, string $key, int $n): array
    {
        $rows = [];
        for ($i = 0; $i < $n; $i++) {
            $rowKey = $key . '#' . $i;
            $person = FakePeople::person($seed, $rowKey);
            $rows[] = [
                self::id($seed, $rowKey . '|orderId'),
                $person['full'],
                self::amount($seed, $rowKey),
                self::STATUSES[self::index($seed, $rowKey . '|status', count(self::STATUSES))],
                FakePeople::date($seed, $rowKey . '|created'),
            ];
        }

        return $rows;
    }

    /** A 5-digit id string (10000-99999): one digit short of the denylist's 6-digit run, so no
     *  value can ever match it regardless of which digits land where. */
    private static function id(int $seed, string $field): string
    {
        return (string) (10000 + self::index($seed, $field, 90000));
    }

    /** `{0-9999}.{00-99}` — a dollar amount under $10,000 with exactly 2 decimal digits. The
     *  '.' splits the cell into two digit runs (max 4 digits, exactly 2 digits), both too short
     *  to ever form the denylist's isolated 6-digit run. */
    private static function amount(int $seed, string $field): string
    {
        $dollars = self::index($seed, $field . '|amountDollars', 10000);
        $cents = self::index($seed, $field . '|amountCents', 100);

        return sprintf('%d.%02d', $dollars, $cents);
    }

    /** Sub-hash index into a range of size $count, independently keyed by $field so sibling
     *  columns for the same row never move in lockstep. */
    private static function index(int $seed, string $field, int $count): int
    {
        return (int) (hexdec(substr(self::hash($seed, $field), 0, 8)) % $count);
    }

    private static function hash(int $seed, string $field): string
    {
        return hash('sha256', $seed . '|record|' . $field);
    }
}
