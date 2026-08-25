<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * diagnose() is what tells an operator whether the compiled index is interned into opcache shared
 * memory or re-materialised on every request — a 0.00 MB vs 20.43 MB per-request difference that
 * nothing else surfaces. It must never throw, whatever the host looks like.
 */
final class StoreDiagnoseTest extends TestCase
{
    public function test_it_always_returns_the_full_shape_and_never_throws(): void
    {
        $d = PhpArrayStore::diagnose();

        foreach (['shared', 'reason', 'remedy', 'sapi', 'shm_free', 'restarts'] as $key) {
            self::assertArrayHasKey($key, $d);
        }
        self::assertIsBool($d['shared']);
        self::assertIsString($d['reason']);
        self::assertIsString($d['remedy']);
        self::assertSame(PHP_SAPI, $d['sapi']);
        self::assertIsInt($d['shm_free']);
        self::assertIsInt($d['restarts']);
    }

    public function test_a_negative_verdict_always_carries_a_reason(): void
    {
        $d = PhpArrayStore::diagnose();

        self::assertNotSame('', $d['reason'], 'a verdict without a reason is unactionable');

        if ($d['shared'] === false) {
            self::assertNotSame('', $d['remedy'], 'telling an operator "no" without a remedy is useless');
        }
    }

    public function test_an_unknown_path_is_reported_not_thrown(): void
    {
        $d = PhpArrayStore::diagnose('/nonexistent/never/here.php');

        self::assertFalse($d['shared']);
        self::assertNotSame('', $d['reason']);
    }
}
