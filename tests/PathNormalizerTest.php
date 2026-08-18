<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Support\PathNormalizer;
use PHPUnit\Framework\TestCase;

final class PathNormalizerTest extends TestCase
{
    public function test_leading_slash_is_guaranteed(): void
    {
        self::assertSame('/.git/config', PathNormalizer::normalize('.git/config'));
        self::assertSame('/.git/config', PathNormalizer::normalize('/.git/config'));
    }

    public function test_empty_path_is_root(): void
    {
        self::assertSame('/', PathNormalizer::normalize(''));
    }

    public function test_query_and_fragment_are_stripped(): void
    {
        self::assertSame('/config/', PathNormalizer::normalize('/config/?a=1'));
        self::assertSame('/x', PathNormalizer::normalize('/x#frag'));
    }

    public function test_trailing_slash_is_preserved(): void
    {
        // /config/ (directory listing) must stay distinct from /config.
        self::assertSame('/config/', PathNormalizer::normalize('/config/'));
        self::assertSame('/config', PathNormalizer::normalize('/config'));
    }

    /**
     * Byte-identity: percent-escapes keep their exact case and are NOT decoded,
     * lowercased, or "../"-collapsed. Scanners probe exact bytes; divergence misses.
     */
    public function test_encoded_traversal_is_byte_identical(): void
    {
        $raw = '/hue/assets/..%2F..%2F..%2Fetc%2fpasswd';
        self::assertSame($raw, PathNormalizer::normalize($raw));
    }

    public function test_invalid_utf8_escape_is_preserved(): void
    {
        self::assertSame('/%c0', PathNormalizer::normalize('/%c0'));
    }

    public function test_key_upcases_method_only(): void
    {
        self::assertSame('GET /.git/config', PathNormalizer::key('get', '/.git/config'));
        self::assertSame('POST /Config/', PathNormalizer::key('post', '/Config/'));
    }
}
