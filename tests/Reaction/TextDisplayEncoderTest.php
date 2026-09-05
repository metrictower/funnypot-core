<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Funnypot\Core\Reaction\TextDisplayEncoder;
use PHPUnit\Framework\TestCase;

/**
 * The plain-text display encoder: a small printable-ASCII set passes through unchanged and every other
 * byte becomes an uppercase \xHH escape, so no control byte, quote or multibyte sequence reaches a
 * text/plain body as itself.
 */
final class TextDisplayEncoderTest extends TestCase
{
    public function test_safe_set_passes_through(): void
    {
        $safe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._:/?=&%+@-';
        self::assertSame($safe, TextDisplayEncoder::encode($safe));
    }

    public function test_markup_bytes_are_escaped_uppercase(): void
    {
        // < > " ' are all outside the safe set.
        self::assertSame('\\x3Cscript\\x3E', TextDisplayEncoder::encode('<script>'));
        self::assertSame('\\x22\\x27', TextDisplayEncoder::encode('"\''));
    }

    public function test_control_bytes_are_escaped(): void
    {
        self::assertSame('a\\x0Db', TextDisplayEncoder::encode("a\rb"));
        self::assertSame('a\\x0Ab', TextDisplayEncoder::encode("a\nb"));
        self::assertSame('a\\x00b', TextDisplayEncoder::encode("a\x00b"));
    }

    public function test_multibyte_is_escaped_byte_wise(): void
    {
        // A 4-byte emoji becomes four \xHH escapes.
        $rocket = "\xF0\x9F\x9A\x80";
        self::assertSame('\\xF0\\x9F\\x9A\\x80', TextDisplayEncoder::encode($rocket));
    }

    public function test_output_is_pure_printable_ascii(): void
    {
        $mixed = "path=/a\r\n<b>caf\xc3\xa9\x00";
        $out = TextDisplayEncoder::encode($mixed);
        self::assertSame(1, preg_match('/^[\x20-\x7e]*$/', $out), 'output must be printable ASCII only');
        self::assertStringNotContainsString('<', $out);
        self::assertStringNotContainsString("\r", $out);
        self::assertStringNotContainsString("\n", $out);
    }

    public function test_hex_is_uppercase(): void
    {
        // 0xab must render as \xAB, never \xab.
        self::assertSame('\\xAB', TextDisplayEncoder::encode("\xab"));
    }
}
