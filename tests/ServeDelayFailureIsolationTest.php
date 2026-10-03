<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

final class ServeDelayFailureIsolationTest extends TestCase
{
    public function test_loading_failure_fixture_does_not_install_entropy_shims(): void
    {
        require_once __DIR__ . '/ServeDelayFailureTest.php';

        self::assertFalse(function_exists('Funnypot\\Core\\random_int'));
        self::assertFalse(function_exists('Funnypot\\Core\\random_bytes'));
        self::assertFalse(function_exists('Funnypot\\Core\\Synthesis\\random_bytes'));
    }
}
