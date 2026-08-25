<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Support\PathNormalizer;
use PHPUnit\Framework\TestCase;

/**
 * ownershipKey() is the single canonical form both the compiler (owns_path emission) and the engine
 * (ownsPath lookup) key on, so a case/trailing-slash probe variant that resolveEntry can hit the
 * store with still resolves to the same ownership key.
 */
final class PathNormalizerOwnershipTest extends TestCase
{
    public function test_ownership_key_lowercases_and_strips_trailing_slash(): void
    {
        self::assertSame('/xmlrpc.php', PathNormalizer::ownershipKey('/xmlrpc.php'));
        self::assertSame('/xmlrpc.php', PathNormalizer::ownershipKey('/XMLRPC.PHP'));
        self::assertSame('/xmlrpc.php', PathNormalizer::ownershipKey('/xmlrpc.php/'));
        self::assertSame('/xmlrpc.php', PathNormalizer::ownershipKey('/XmlRpc.PHP/'));
    }

    public function test_ownership_key_preserves_root(): void
    {
        self::assertSame('/', PathNormalizer::ownershipKey('/'));
    }
}
