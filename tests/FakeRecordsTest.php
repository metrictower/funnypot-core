<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Support\Fake\FakeRecords;
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
                (bool) preg_match('/^AKIA[A-Z0-9]{16}$/', $secret)
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
