<?php

declare(strict_types=1);

namespace Funnypot\Core\Behavior;

use Funnypot\Core\Support\SubSeed;

/**
 * The closed per-deploy vocabulary for the mock-auth decoy session's signed state token (FP-0296).
 *
 * The decoy cookie's NAME, path, attributes and 16-hex HMAC envelope stay fixed per product; only the
 * signed state text varies. A fleet-constant state text (the old literal `s=0`/`s=1`) is a fingerprint
 * tell, so one deploy-seeded index selects ONE reviewed row from the table below. Each row carries
 * THREE strictly-distinct payload classes: pre-auth (visited the login page), 2fa-pending (password
 * accepted, verification code not yet entered), and authenticated (logged in). Selecting a single
 * index — never independent draws per class — guarantees the three classes can never collapse to the
 * same string, so `authenticated()`, `twoFactorPending()` and `preAuth()` stay strict domain
 * separators from one another for every seed.
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
     * The reviewed pre-auth/2fa-pending/authenticated triples, in fixed order. The chosen index picks
     * one row; its three sides are structurally unequal, so no vocabulary edit can make a class
     * comparison vacuous. The `pre`/`authenticated` texts are unchanged from the original pairs — only
     * the middle `pending` class is new — so a seed's pre-auth and authenticated tokens are byte-stable.
     *
     * @var list<array{pre:string,pending:string,authenticated:string}>
     */
    public const PAIRS = [
        ['pre' => 'state=guest', 'pending' => 'state=challenge', 'authenticated' => 'state=user'],
        ['pre' => 'auth=pending', 'pending' => 'auth=challenge', 'authenticated' => 'auth=valid'],
        ['pre' => 'session=anon', 'pending' => 'session=challenge', 'authenticated' => 'session=active'],
        ['pre' => 'login=guest', 'pending' => 'login=verify', 'authenticated' => 'login=member'],
        ['pre' => 'access=public', 'pending' => 'access=pending', 'authenticated' => 'access=private'],
        ['pre' => 'status=preauth', 'pending' => 'status=challenge', 'authenticated' => 'status=verified'],
        ['pre' => 'mode=visitor', 'pending' => 'mode=pending', 'authenticated' => 'mode=member'],
        ['pre' => 'role=anonymous', 'pending' => 'role=pending', 'authenticated' => 'role=user'],
        ['pre' => 'member=no', 'pending' => 'member=maybe', 'authenticated' => 'member=yes'],
        ['pre' => 'active=0', 'pending' => 'active=2', 'authenticated' => 'active=1'],
        ['pre' => 'logged_in=0', 'pending' => 'logged_in=2', 'authenticated' => 'logged_in=1'],
        ['pre' => 'identity=guest', 'pending' => 'identity=pending', 'authenticated' => 'identity=known'],
        ['pre' => 'account=visitor', 'pending' => 'account=pending', 'authenticated' => 'account=user'],
        ['pre' => 'verified=no', 'pending' => 'verified=maybe', 'authenticated' => 'verified=yes'],
        ['pre' => 'principal=guest', 'pending' => 'principal=pending', 'authenticated' => 'principal=member'],
        ['pre' => 'session_state=initial', 'pending' => 'session_state=challenge', 'authenticated' => 'session_state=active'],
    ];

    /**
     * The selected triple for a deploy seed. `null` maps explicitly to integer seed `0` so the
     * constructor/method arity stays source-compatible for direct library tests and legacy callers;
     * that fallback is not a production source of deploy variance — every production path supplies an
     * integer identity seed.
     *
     * @return array{pre:string,pending:string,authenticated:string}
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

    /** The 2fa-pending (password accepted, code not yet entered) state text for a deploy seed. */
    public static function twoFactorPending(?int $deploySeed): string
    {
        return self::pair($deploySeed)['pending'];
    }

    /** The authenticated (logged-in) state text for a deploy seed. */
    public static function authenticated(?int $deploySeed): string
    {
        return self::pair($deploySeed)['authenticated'];
    }
}
