<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * FP-0472 (detection slice): a signal-only detector for SSRF PROTOCOL-SMUGGLING payloads — an attacker
 * wrapping a raw TCP byte-stream in a non-HTTP URI scheme (gopher:// / dict:// / tftp:// / ldap://) to
 * talk directly to an internal service (Redis, PHP-FPM/FastCGI, Memcached, Zabbix) through an SSRF sink.
 *
 * Wired into classify() via OobSignalRegistry and folded by foldOob(), so the baseline response stays
 * BYTE-IDENTICAL — a smuggling probe gets exactly the response a benign request would, with no
 * differential "this endpoint reacts to my payload" tell (security invariant #1). This is the DETECTION
 * half only. The deceptive protocol responder (a synthetic +OK/STORED/FastCGI ack in a reflection sink)
 * and structured LHOST/LPORT telemetry serve DIFFERENT bytes / need the observer evidence channel and an
 * SSRF-fetch seam (blind SSRF confirms out-of-band, not via the HTTP body) — deferred to the app tier.
 *
 * Clean-room: these are the attack payloads' OWN framing/command tokens (facts), MATCHED here, never
 * served and never a vendored tool file. Detection-only: pure pattern matching over the bounded,
 * percent-decoded OobHaystack (path + query + every header value + body; gopher %0d%0a framing decodes to
 * CRLF), no I/O / config / state (the OobSignalRegistry contract). PHP 7.3-safe.
 *
 * FP discipline: every family requires BOTH a non-HTTP wrapper scheme AND a family-specific encapsulated
 * marker, so a benign gopher/dict link with no smuggled command, or the word "flushall" in prose without
 * a wrapper, never matches. Families are tested in a fixed order; the first hit wins.
 */
final class SsrfSmugglingProbe
{
    public const REDIS = 'redis';
    public const FASTCGI = 'fastcgi';
    public const MEMCACHED = 'memcached';
    public const ZABBIX = 'zabbix';
    public const DICT = 'dict';

    /** A smuggled stream is always wrapped in one of these non-HTTP URI schemes. */
    private const WRAPPER = '~(?:gopher|dict|tftp|ldap)://~i';

    /**
     * Family markers (each additionally gated by WRAPPER). RESP framing %2A/%24 decodes to *,$ so both the
     * encoded and decoded forms are seen. Redis `config set dir|dbfilename`/`flushall`/`slaveof` = the
     * cron/rdb webshell drop; FastCGI PHP_VALUE/auto_prepend_file/allow_url_include = the PHP-FPM RCE set;
     * Memcached `set <k> <flags> <exp> <bytes>` framing; Zabbix `system.run[` = agent command exec.
     *
     * @var array<string,string>
     */
    private const FAMILY = [
        self::REDIS => '~\bflushall\b|config\s+set\s+(?:dir|dbfilename)\b|\bslaveof\b|\breplicaof\b'
            . '|\*\d+\r\n\$\d+\r\n(?:set|config|flushall|slaveof|replicaof)~i',
        self::FASTCGI => '~php_value\b|auto_prepend_file\b|allow_url_include\b|fcgi_begin_request'
            . '|\x01\x01\x00\x01\x00\x08~i',
        self::MEMCACHED => '~\bset\s+\S+\s+\d+\s+\d+\s+\d+\r\n|:11211\b~i',
        self::ZABBIX => '~system\.run\[~i',
        self::DICT => '~dict://[^/\s]+/[a-z]+:~i',
    ];

    /**
     * @return string|null one of the family constants, or null when no smuggled stream is present
     */
    public static function detect(RequestContext $r): ?string
    {
        $haystack = OobHaystack::build($r);
        if (preg_match(self::WRAPPER, $haystack) !== 1) {
            return null;
        }
        foreach (self::FAMILY as $family => $pattern) {
            if (preg_match($pattern, $haystack) === 1) {
                return $family;
            }
        }

        return null;
    }
}
