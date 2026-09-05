<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

/**
 * Display-only encoding for a reaction value placed into a text/plain body — the plain-text counterpart
 * of Esc::text() for HTML. It keeps a small printable-ASCII set and rewrites EVERY other byte as an
 * uppercase `\xHH` escape, so no control byte, quote or multibyte sequence reaches the served body as
 * itself. Multibyte UTF-8 is escaped byte-wise (a 4-byte emoji becomes four `\xHH`). This is display
 * text, never executed and never re-decoded.
 *
 * The parser already rejected CR/LF/NUL/controls in a recognized value, so this is defense-in-depth
 * for the header-safety and no-tell invariants rather than the only guard.
 *
 * 7.3-safe: preg_replace_callback/bin2hex only.
 */
final class TextDisplayEncoder
{
    private function __construct()
    {
    }

    public static function encode(string $value): string
    {
        // Byte-wise (no /u): any byte outside the safe set — including every byte of a multibyte
        // sequence — becomes \xHH. '-' sits last in the class so it is a literal, not a range.
        return (string) preg_replace_callback(
            '/[^A-Za-z0-9 ._:\/?=&%+@-]/',
            static function (array $m): string {
                return '\\x' . strtoupper(bin2hex($m[0]));
            },
            $value
        );
    }
}
