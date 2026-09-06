<?php

declare(strict_types=1);

namespace Funnypot\Core\Behavior;

use Funnypot\Core\Support\SubSeed;

/**
 * The closed per-deploy vocabulary for the mock-auth decoy session's signed state token (FP-0296).
 *
 * The decoy cookie's NAME, path, attributes and 16-hex HMAC envelope stay fixed per product; only the
 * signed state text varies. A fleet-constant state text (the old literal `s=0`/`s=1`) is a fingerprint
 * tell, so one deploy-seeded index selects ONE reviewed pre-auth/authenticated PAIR from the table
 * below. Selecting a single index — never two independent draws — guarantees the two classes can never
 * collapse to the same string, so `authenticated()` stays a strict domain separator from `preAuth()`.
 *
 * The vocabulary is realistic low-entropy application-state wording, cookie-safe ASCII (before URL
 * encoding), denylist-clean, and carries no scanner/matcher signature; the pool is NOT the security
 * boundary (the HMAC is) — it only removes a cross-fleet constant. There is no entropy primitive here:
 * `pair()` derives from the seed alone (no `SubSeed::int`, request byte, clock or CSPRNG), so a render
 * is byte-stable per deploy.
 *
 * PHP 7.3-safe: `?int` param, array-shape docblock, static methods only.
 */
final class DecoySessionPayloads
{
    /**
     * The reviewed pre-auth/authenticated pairs, in fixed order. The chosen index picks one row; its
     * two sides are structurally unequal, so no vocabulary edit can make a class comparison vacuous.
     *
     * @var list<array{pre:string,authenticated:string}>
     */
    public const PAIRS = [
        ['pre' => 'state=guest', 'authenticated' => 'state=user'],
        ['pre' => 'auth=pending', 'authenticated' => 'auth=valid'],
        ['pre' => 'session=anon', 'authenticated' => 'session=active'],
        ['pre' => 'login=guest', 'authenticated' => 'login=member'],
        ['pre' => 'access=public', 'authenticated' => 'access=private'],
        ['pre' => 'status=preauth', 'authenticated' => 'status=verified'],
        ['pre' => 'mode=visitor', 'authenticated' => 'mode=member'],
        ['pre' => 'role=anonymous', 'authenticated' => 'role=user'],
        ['pre' => 'member=no', 'authenticated' => 'member=yes'],
        ['pre' => 'active=0', 'authenticated' => 'active=1'],
        ['pre' => 'logged_in=0', 'authenticated' => 'logged_in=1'],
        ['pre' => 'identity=guest', 'authenticated' => 'identity=known'],
        ['pre' => 'account=visitor', 'authenticated' => 'account=user'],
        ['pre' => 'verified=no', 'authenticated' => 'verified=yes'],
        ['pre' => 'principal=guest', 'authenticated' => 'principal=member'],
        ['pre' => 'session_state=initial', 'authenticated' => 'session_state=active'],
    ];

    /**
     * The selected pair for a deploy seed. `null` maps explicitly to integer seed `0` so the
     * constructor/method arity stays source-compatible for direct library tests and legacy callers;
     * that fallback is not a production source of deploy variance — every production path supplies an
     * integer identity seed.
     *
     * @return array{pre:string,authenticated:string}
     */
    public static function pair(?int $deploySeed): array
    {
        $seed = $deploySeed ?? 0;
        $i = SubSeed::index($seed, SubSeed::NS_DECOY, 'session|payload-pair', count(self::PAIRS));

        return self::PAIRS[$i];
    }

    /** The pre-auth (visited-the-login-page) state text for a deploy seed. */
    public static function preAuth(?int $deploySeed): string
    {
        return self::pair($deploySeed)['pre'];
    }

    /** The authenticated (logged-in) state text for a deploy seed. */
    public static function authenticated(?int $deploySeed): string
    {
        return self::pair($deploySeed)['authenticated'];
    }
}
