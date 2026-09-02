<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * The seeded ENVELOPE around the honeytoken bait cookie (FP-0282): its name, its payload vocabulary
 * (key=role), and its attribute tail. The 16-hex HMAC VALUE stays the load-bearing tamper token
 * (Honeytoken::sign is over the payload + key only) — the envelope never enters the HMAC, so it can vary
 * freely per deploy as long as the SAME deploy plants and reads it (a pure function of the deploy seed
 * gives that round-trip). This turns the former fleet constant `sess=r%3Duser…; path=/; HttpOnly` into
 * a per-deploy shape, so the bait cookie is no longer a cross-fleet regex.
 *
 * HYGIENE (tested):
 *  - NAMES are session-cookie-shaped, cookie-token chars only ([A-Za-z0-9_-], no '.', so $_COOKIE keys
 *    are verbatim), denylist-clean, and DISJOINT from every name another tier plants — the route E2
 *    cookies (`set_cookie:` in templates/route) and the decoy-session names (phpMyAdmin,
 *    wordpress_logged_in_*) — a collision would let one cookie clobber the other in the browser jar.
 *  - ROLES name a LOW role only (the escalation bait): no admin/root/super/owner class word may enter,
 *    so the lure still visibly names a low-privilege session an attacker is tempted to escalate.
 *  - ATTRS are shapes a real PHP stack emits: PHP setcookie() (`; path=/; HttpOnly`, optionally with
 *    `; SameSite=Lax|Strict`) and the Symfony/Laravel Cookie::__toString lowercase form
 *    (`; path=/; httponly; samesite=lax`). `Secure` is deliberately absent (an http deploy that sends it
 *    is a tell); `HttpOnly` is always present (the session-cookie shape the lure imitates); `path=/`
 *    (lowercase, matching PHP's setcookie output) is the single substitution point for the scope path.
 *
 * DETERMINISM: every draw is SubSeed::pick under NS_HONEYTOKEN (index/pick only; never SubSeed::int, no
 * clock/CSPRNG/request byte). PHP 7.3-safe.
 */
final class HoneytokenEnvelope
{
    /** @var list<string> */
    public const NAMES = ['sess', 'sid', 'SESSID', 'session', 'sessid', 'app_session', 'sess_id', 'ci_session', '_session_id', 'usid', 'SESS', 'ssid'];

    /** @var list<string> */
    public const KEYS = ['r', 'role', 'lvl', 'acl', 'grp', 'u'];

    /** @var list<string> */
    public const ROLES = ['user', 'member', 'std', 'basic', 'guest', 'viewer'];

    /** Four DISTINCT attribute tails (the duplicate SameSite=Lax entry from the plan is deduped). Each
     *  carries a `path=/` substitution point.
     *
     * @var list<string> */
    public const ATTRS = [
        '; path=/; HttpOnly',
        '; path=/; HttpOnly; SameSite=Lax',
        '; path=/; HttpOnly; SameSite=Strict',
        '; path=/; httponly; samesite=lax',
    ];

    private function __construct()
    {
    }

    /** The bait cookie name for this deploy. */
    public static function name(int $deploySeed): string
    {
        return SubSeed::pick(self::NAMES, $deploySeed, SubSeed::NS_HONEYTOKEN, 'bait|name');
    }

    /** The bait payload `key=role` for this deploy — a signed low-role session marker. */
    public static function payload(int $deploySeed): string
    {
        return SubSeed::pick(self::KEYS, $deploySeed, SubSeed::NS_HONEYTOKEN, 'bait|key')
            . '='
            . SubSeed::pick(self::ROLES, $deploySeed, SubSeed::NS_HONEYTOKEN, 'bait|role');
    }

    /** The attribute tail for this deploy, with its `path=/` scope replaced by $path. */
    public static function attributes(int $deploySeed, string $path = '/'): string
    {
        $attr = SubSeed::pick(self::ATTRS, $deploySeed, SubSeed::NS_HONEYTOKEN, 'bait|attrs');
        $pos = strpos($attr, 'path=/');
        if ($pos !== false) {
            $attr = substr($attr, 0, $pos) . 'path=' . $path . substr($attr, $pos + strlen('path=/'));
        }

        return $attr;
    }
}
