<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * How a fake response is dressed. Every style still satisfies the compiled matchers
 * (so the scanner reports "vulnerable"); they differ only in the body around the
 * required tokens.
 *
 *  - MINIMAL   : terse — just the tokens a matcher needs. Smallest, safest, the proven
 *                default; no emulator layer runs.
 *  - REALISTIC : plausible-but-fake data (a believable .env / .git/config / xmlrpc
 *                response) so a human poking the "finding" keeps digging. Values are
 *                obviously inert to us (example.com, RFC-5737 IPs, dummy keys) — never a
 *                real or working secret.
 *  - TAUNT     : still satisfies the matcher (scanner still fires, time still wasted) but
 *                also carries a visible "nice try" marker so a human sees the decoy.
 */
final class Style
{
    public const MINIMAL = 'minimal';
    public const REALISTIC = 'realistic';
    public const TAUNT = 'taunt';

    public const ALL = [self::MINIMAL, self::REALISTIC, self::TAUNT];

    public static function isValid(string $style): bool
    {
        return in_array($style, self::ALL, true);
    }
}
