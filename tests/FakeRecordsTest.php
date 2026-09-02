<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\Fake\FakeRecords;
use PHPUnit\Framework\TestCase;

/**
 * Table rows for the mock-auth panels, built on FakePeople + FakeSecrets: each row is a pure
 * function of (seed, key, rowIndex), so a table renders identically every fetch for one deploy
 * and diverges across deploys (different seed) or panels (different key).
 */
final class FakeRecordsTest extends TestCase
{
    public function test_users_is_deterministic_and_shaped(): void
    {
        $rows = FakeRecords::users(1, 'acme.test', 'users', 5);
        self::assertSame($rows, FakeRecords::users(1, 'acme.test', 'users', 5));
        self::assertCount(5, $rows);

        foreach ($rows as $row) {
            self::assertCount(4, $row);
            [$id, $username, $email, $createdAt] = $row;
            self::assertMatchesRegularExpression('/^\d{5}$/', $id);
            self::assertNotSame('', $username);
            self::assertStringEndsWith('@acme.test', $email);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $createdAt);
        }
    }

    public function test_users_differs_across_seeds(): void
    {
        self::assertNotSame(
            FakeRecords::users(1, 'acme.test', 'users', 5),
            FakeRecords::users(2, 'acme.test', 'users', 5)
        );
    }

    public function test_password_resets_is_deterministic_and_shaped(): void
    {
        $rows = FakeRecords::passwordResets(3, 'acme.test', 'resets', 4);
        self::assertSame($rows, FakeRecords::passwordResets(3, 'acme.test', 'resets', 4));
        self::assertCount(4, $rows);

        foreach ($rows as $row) {
            self::assertCount(4, $row);
            [$email, $token, $requestedAt, $expiresAt] = $row;
            self::assertStringEndsWith('@acme.test', $email);
            self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/', $token);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $requestedAt);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $expiresAt);
        }
    }

    public function test_api_keys_is_deterministic_and_shaped(): void
    {
        $rows = FakeRecords::apiKeys(4, 'keys', 6);
        self::assertSame($rows, FakeRecords::apiKeys(4, 'keys', 6));
        self::assertCount(6, $rows);

        foreach ($rows as $row) {
            self::assertCount(5, $row);
            [$id, $owner, $secret, $createdAt, $lastUsedAt] = $row;
            self::assertMatchesRegularExpression('/^\d{5}$/', $id);
            self::assertNotSame('', $owner);
            self::assertTrue(
                (bool) preg_match('/^AKIA[A-Z2-7]{16}$/', $secret)
                || (bool) preg_match('/^sk_test_[A-Za-z0-9]{24}$/', $secret),
                "unexpected secret shape: {$secret}"
            );
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $createdAt);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $lastUsedAt);
        }
    }

    public function test_sessions_is_deterministic_and_shaped(): void
    {
        $rows = FakeRecords::sessions(5, 'acme.test', 'sessions', 5);
        self::assertSame($rows, FakeRecords::sessions(5, 'acme.test', 'sessions', 5));
        self::assertCount(5, $rows);

        foreach ($rows as $row) {
            self::assertCount(4, $row);
            [$id, $username, $ip, $lastActivity] = $row;
            self::assertMatchesRegularExpression('/^\d{5}$/', $id);
            self::assertNotSame('', $username);
            self::assertMatchesRegularExpression('/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/', $ip);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $lastActivity);
        }
    }

    public function test_sessions_differs_across_domains(): void
    {
        self::assertNotSame(
            FakeRecords::sessions(5, 'acme.test', 'sessions', 5),
            FakeRecords::sessions(5, 'other.test', 'sessions', 5)
        );
    }

    public function test_orders_is_deterministic_and_shaped(): void
    {
        $rows = FakeRecords::orders(6, 'orders', 6);
        self::assertSame($rows, FakeRecords::orders(6, 'orders', 6));
        self::assertCount(6, $rows);

        $statuses = ['pending', 'paid', 'shipped', 'refunded', 'cancelled'];
        foreach ($rows as $row) {
            self::assertCount(5, $row);
            [$orderId, $customer, $amount, $status, $createdAt] = $row;
            self::assertMatchesRegularExpression('/^\d{5}$/', $orderId);
            self::assertNotSame('', $customer);
            self::assertMatchesRegularExpression('/^\d{1,4}\.\d{2}$/', $amount);
            self::assertContains($status, $statuses);
            self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}$/', $createdAt);
        }
    }

    /** Pinned at the SHIPPED decoy row count (attack rule 102 authors rows: 8), so the test can no
     *  longer pass on a smaller fixture while production duplicates labels. */
    public function test_secrets_is_deterministic_unique_and_shaped_at_shipped_row_count(): void
    {
        $rows = FakeRecords::secrets(7, 'secrets', 8);
        self::assertSame($rows, FakeRecords::secrets(7, 'secrets', 8));
        self::assertCount(8, $rows);

        $names = [];
        foreach ($rows as $row) {
            self::assertCount(3, $row);
            [$id, $name, $value] = $row;
            self::assertMatchesRegularExpression('/^\d{5}$/', $id);
            $names[] = $name;
            self::assertMatchesRegularExpression(self::secretValuePattern($name), $value, "value shape for {$name}");
        }
        // Every label is distinct across the 8-row table — no two rows share a `name` (and so never
        // two different values for one `ctf_flag`).
        self::assertSame(count($names), count(array_unique($names)), 'secret labels must be unique per render');
    }

    /** The row count is clamped to the distinct-label count, so a render beyond it (or the shipped
     *  rows: 8) never repeats a label — robust for any n >= count(labels). */
    public function test_secrets_row_count_is_clamped_to_the_label_count(): void
    {
        $rows = FakeRecords::secrets(42, 'secrets', 25);
        $names = array_map(static function (array $r): string {
            return $r[1];
        }, $rows);
        self::assertSame(count($names), count(array_unique($names)), 'no duplicate label even when n exceeds the label count');
        // Exactly one ctf_flag (the reviewer's seed-42 duplicate-flag regression).
        self::assertLessThanOrEqual(1, count(array_filter($names, static function (string $n): bool {
            return $n === 'ctf_flag';
        })), 'a table must never carry two different ctf_flag values');
    }

    /** The regex a secrets `value` must match given its label — flag / bcrypt / AWS-key / 40-hex. */
    private static function secretValuePattern(string $label): string
    {
        if (substr($label, -5) === '_flag') {
            return '/^FLAG\.\{[0-9a-f]{40}\}\.GALF$/';
        }
        if (strpos($label, 'password') !== false) {
            // Legal bcrypt alphabet: `./A-Za-z0-9` (the FP-0260 fix adds `.`/`/`, which the old
            // `[A-Za-z0-9]` regex would hard-fail on the moment they appear).
            return '#^\$2y\$10\$[./A-Za-z0-9]{53}$#';
        }
        if (strpos($label, 'api') !== false) {
            // Base32 body `[A-Z2-7]` — a real AWS access-key-id never carries 0/1/8/9.
            return '/^AKIA[A-Z2-7]{16}$/';
        }

        return '/^[0-9a-f]{40}$/';
    }

    public function test_secrets_differs_across_seeds_and_keys(): void
    {
        self::assertNotSame(FakeRecords::secrets(7, 'secrets', 3), FakeRecords::secrets(8, 'secrets', 3));
        self::assertNotSame(FakeRecords::secrets(7, 'secrets-a', 3), FakeRecords::secrets(7, 'secrets-b', 3));
    }

    public function test_different_keys_yield_different_rows_for_same_row_index(): void
    {
        $a = FakeRecords::orders(6, 'orders-a', 1);
        $b = FakeRecords::orders(6, 'orders-b', 1);
        self::assertNotSame($a, $b);
    }

    /**
     * The runtime fingerprint scan denylists a bare CRS rule id: six digits starting with 9,
     * bounded by non-word characters (resources/fingerprint-denylist.php). No cell in any of
     * these five row generators may ever expose that shape, across a wide seed spread.
     */
    public function test_no_cell_matches_the_fingerprint_denylist_across_many_seeds(): void
    {
        $pattern = self::denylistPattern();

        for ($seed = 0; $seed < 256; $seed++) {
            $rowSets = [
                FakeRecords::users($seed, 'acme.test', 'users', 3),
                FakeRecords::passwordResets($seed, 'acme.test', 'resets', 3),
                FakeRecords::apiKeys($seed, 'keys', 3),
                FakeRecords::sessions($seed, 'acme.test', 'sessions', 3),
                FakeRecords::orders($seed, 'orders', 3),
                FakeRecords::secrets($seed, 'secrets', 3),
            ];

            foreach ($rowSets as $rows) {
                foreach ($rows as $row) {
                    foreach ($row as $cell) {
                        self::assertDoesNotMatchRegularExpression(
                            $pattern,
                            $cell,
                            "seed={$seed} cell={$cell}"
                        );
                    }
                }
            }
        }
    }

    private static function denylistPattern(): string
    {
        $denylist = require dirname(__DIR__) . '/resources/fingerprint-denylist.php';
        foreach ($denylist['patterns'] as $p) {
            if ($p === '\b9\d{5}\b') {
                return '/' . $p . '/i';
            }
        }

        self::fail('expected \b9\d{5}\b pattern not found in fingerprint-denylist.php');
    }
}
