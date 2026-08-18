<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Detect a Log4Shell / JNDI lookup probe anywhere in a request. This is a DETECT-ONLY
 * signal: the exploit's proof is an out-of-band JNDI/LDAP callback, which a reflect-only
 * responder cannot fake — so funnypot never "responds vulnerable" to it, it just flags the
 * probe (high value for threat intel). Handles the common obfuscations attackers wrap the
 * lookup in (`${lower:j}ndi`, `${::-j}`, nested `${${...}}`, env/sys resolvers).
 */
final class Log4ShellProbe
{
    private const PATTERN = '/\$\{[^}]{0,40}(?:jndi|ldap|rmi|dns|lower:|upper:|env:|sys:|date:|\$\{)/i';

    public static function present(RequestContext $r): bool
    {
        // JNDI probes are usually planted in a header (User-Agent, X-Api-Version, Referer…),
        // but check the query and body too. Cap the surface — it's authored-regex vs attacker
        // input, and a probe is short.
        $hay = $r->query . ' ' . (string) ($r->rawBody ?? '');
        foreach ($r->headers as $value) {
            $hay .= ' ' . (string) $value;
        }
        if (strlen($hay) > 16384) {
            $hay = substr($hay, 0, 16384);
        }

        return preg_match(self::PATTERN, $hay) === 1;
    }
}
