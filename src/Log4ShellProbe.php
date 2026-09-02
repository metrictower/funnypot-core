<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * Detect a Log4Shell / JNDI lookup probe anywhere in a request. This is a DETECT-ONLY
 * signal: the exploit's proof is an out-of-band JNDI/LDAP callback, which a reflect-only
 * responder cannot fake — so funnypot never "responds vulnerable" to it, it just flags the
 * probe (high value for threat intel). Handles the common obfuscations attackers wrap the
 * lookup in (`${lower:j}ndi`, `${::-j}`, nested `${${...}}`, env/sys resolvers).
 *
 * Wired into classify() via OobSignalRegistry (FP-0256): detect() returns a severity
 * mode so the registry can split the telemetry — a byte-provable JNDI scheme is CONFIRMED
 * (critical), a resolver-wrapped lookup that never names a scheme is RESOLVER (high).
 * Signal-only: pure pattern matching over the shared OobHaystack, no I/O.
 */
final class Log4ShellProbe
{
    /** ${...jndi / ldap / rmi / dns => a byte-provable lookup scheme (critical). */
    public const CONFIRMED = 'jndi-confirmed';

    /** ${...lower:/upper:/env:/sys:/date:/${ => resolver-wrapped recon, no scheme (high). */
    public const RESOLVER = 'jndi-resolver';

    // The union of these two patterns is EXACTLY the old single PATTERN, so present() is
    // unchanged. CONFIRMED is tested first: a `${jndi:ldap://…}` names a scheme outright;
    // the obfuscated `${${lower:j}ndi:dns://x/y}` cannot — `[^}]` can't cross the inner `}`
    // to reach a scheme word, so it falls to RESOLVER (real recon, not a provable jndi hit).
    private const CONFIRMED_PATTERN = '/\$\{[^}]{0,40}(?:jndi|ldap|rmi|dns)/i';
    private const RESOLVER_PATTERN  = '/\$\{[^}]{0,40}(?:lower:|upper:|env:|sys:|date:|\$\{)/i';

    /**
     * The severity mode of a JNDI probe, or null when none is present. JNDI probes are
     * usually planted in a header (User-Agent, X-Api-Version, Referer…), but the shared
     * OobHaystack scans the path, query, header values, and body too (header-first, capped).
     */
    public static function detect(RequestContext $r): ?string
    {
        $hay = OobHaystack::raw($r);

        if (preg_match(self::CONFIRMED_PATTERN, $hay) === 1) {
            return self::CONFIRMED;
        }
        if (preg_match(self::RESOLVER_PATTERN, $hay) === 1) {
            return self::RESOLVER;
        }

        return null;
    }

    /** Back-compat shim (AntiFingerprintTest calls this directly). */
    public static function present(RequestContext $r): bool
    {
        return self::detect($r) !== null;
    }
}
