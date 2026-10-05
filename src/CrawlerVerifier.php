<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * FP-0360: forward-confirmed reverse-DNS verification of a CLAIMED good-bot crawler, spoof-resistant.
 *
 * A User-Agent is free text — anyone can send Googlebot's. {@see BotSignalSet::UA_GOOD_BOT} is therefore a
 * CLAIM, never proof. The real test is forward-confirmed rDNS: resolve the client IP's PTR to a hostname,
 * require that hostname to sit under the crawler's official DNS suffix, then forward-resolve that hostname
 * (A for IPv4, AAAA for IPv6) and require the result to include the client IP. Only then is the crawler
 * VERIFIED. A claimant that fails any step is an IMPERSONATOR — a high-value deception/report target.
 *
 * This is a PURE function of (ip, user-agent, resolver): DNS is I/O and not core's job, so the caller injects
 * a resolver closure (the app owns the real lookups, caching and timeouts; tests inject a fake). Every
 * resolver fault or mismatch FAILS CLOSED to IMPERSONATOR — a resolver error never upgrades a claimant to
 * verified, and never blocks or leaks the honeypot's presence (the caller decides what to do with the
 * verdict). Verification runs only for a UA that claims a trusted crawler and only for a global client IP;
 * a private/reserved IP presenting a crawler UA is bogus by construction.
 *
 * Clean-room: the forward-confirmation technique and the official crawler DNS suffixes are public facts
 * (each vendor documents its own verify-by-rDNS suffix); this authors its own list and logic.
 */
final class CrawlerVerifier
{
    /** The UA claims a trusted crawler AND forward-confirmed rDNS matches the client IP. */
    public const VERIFIED = 'verified';

    /** The UA claims a trusted crawler but rDNS is absent / off-suffix / forward-mismatched / errored. */
    public const IMPERSONATOR = 'impersonator';

    /** The UA claims no trusted crawler — rDNS verification does not apply. */
    public const NOT_CLAIMED = 'not-claimed';

    /**
     * Lowercase UA token (the crawler's claim) => its official rDNS hostname suffixes (lowercase, dot-anchored
     * so `evilgooglebot.com` cannot pass `.googlebot.com`). Each vendor publishes these for verify-by-rDNS.
     */
    private const TRUSTED = [
        'googlebot'   => ['.googlebot.com', '.google.com'],
        'bingbot'     => ['.search.msn.com'],
        'yandex'      => ['.yandex.ru', '.yandex.net', '.yandex.com'],
        'baiduspider' => ['.crawl.baidu.com', '.crawl.baidu.jp'],
        'duckduckbot' => ['.duckduckgo.com'],
        'applebot'    => ['.applebot.apple.com'],
        'slurp'       => ['.crawl.yahoo.net'],
    ];

    private function __construct()
    {
    }

    /**
     * @param callable(string,string):array<int,string> $resolver ($type in {ptr,a,aaaa}, $query) => records;
     *        may throw or return [] — both fail closed. The app injects real DNS (cached, timeout-bounded);
     *        tests inject a fake map.
     * @return self::VERIFIED|self::IMPERSONATOR|self::NOT_CLAIMED
     */
    public static function verify(string $ip, string $userAgent, callable $resolver): string
    {
        $token = self::claimedCrawler($userAgent);
        if ($token === null) {
            return self::NOT_CLAIMED;
        }
        // A trusted-crawler UA from a non-global IP (private/reserved/loopback) can never be the real crawler.
        if (!self::isGlobalIp($ip)) {
            return self::IMPERSONATOR;
        }

        $names = self::resolveSafe($resolver, 'ptr', $ip);
        $suffixes = self::TRUSTED[$token];
        $wantV6 = strpos($ip, ':') !== false;
        foreach ($names as $name) {
            $host = rtrim(strtolower(trim((string) $name)), '.');
            if ($host === '' || !self::endsWithAny($host, $suffixes)) {
                continue;
            }
            // Forward-confirm: the PTR hostname must itself resolve back to the client IP.
            foreach (self::resolveSafe($resolver, $wantV6 ? 'aaaa' : 'a', $host) as $addr) {
                if (self::sameIp((string) $addr, $ip)) {
                    return self::VERIFIED;
                }
            }
        }

        return self::IMPERSONATOR;
    }

    /** The trusted-crawler token a UA claims (first match), or null. Matched case-insensitively, input-side. */
    private static function claimedCrawler(string $userAgent): ?string
    {
        $ua = strtolower($userAgent);
        foreach (array_keys(self::TRUSTED) as $token) {
            if (strpos($ua, $token) !== false) {
                return $token;
            }
        }

        return null;
    }

    /** A valid, globally-routable IP (not private, not reserved/loopback/link-local). v4 and v6. */
    private static function isGlobalIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    /** @param string[] $suffixes */
    private static function endsWithAny(string $host, array $suffixes): bool
    {
        foreach ($suffixes as $suffix) {
            $len = strlen($suffix);
            if ($len !== 0 && strlen($host) >= $len && substr_compare($host, $suffix, -$len) === 0) {
                return true;
            }
        }

        return false;
    }

    /** Byte-equal IPs after normalisation (so `2001:db8::1` == `2001:0db8:0:0:0:0:0:1`). */
    private static function sameIp(string $a, string $b): bool
    {
        $pa = @inet_pton($a);
        $pb = @inet_pton($b);

        return $pa !== false && $pb !== false && $pa === $pb;
    }

    /**
     * @param callable(string,string):array<int,string> $resolver
     * @return array<int,string> records, or [] on any fault (fail closed)
     */
    private static function resolveSafe(callable $resolver, string $type, string $query): array
    {
        try {
            $out = $resolver($type, $query);
        } catch (\Throwable $e) {
            return [];
        }

        return is_array($out) ? $out : [];
    }
}
