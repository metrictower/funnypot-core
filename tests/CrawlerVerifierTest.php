<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\CrawlerVerifier;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * FP-0360: forward-confirmed-rDNS good-bot verification. A pure function of (ip, user-agent, resolver): the
 * resolver is injected (DNS is the host's I/O, never core's), so these tests drive it with a fake map and
 * assert the spoof-resistance contract — a claimant is VERIFIED only when PTR → official-suffix hostname →
 * forward-resolves back to the client IP; every absent/off-suffix/mismatched/errored case fails closed to
 * IMPERSONATOR; a non-crawler UA is NOT_CLAIMED.
 */
final class CrawlerVerifierTest extends TestCase
{
    /** @param array<string,array<int,string>> $map keyed "type:lower-query" */
    private function resolver(array $map): callable
    {
        return static function (string $type, string $query) use ($map): array {
            return $map[$type . ':' . strtolower($query)] ?? [];
        };
    }

    public function test_real_googlebot_is_verified(): void
    {
        $r = $this->resolver([
            'ptr:66.249.66.1' => ['crawl-66-249-66-1.googlebot.com.'],
            'a:crawl-66-249-66-1.googlebot.com' => ['66.249.66.1'],
        ]);
        self::assertSame(CrawlerVerifier::VERIFIED, CrawlerVerifier::verify('66.249.66.1', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', $r));
    }

    public function test_each_trusted_crawler_verifies_on_its_suffix(): void
    {
        $cases = [
            ['203.0.113.10', 'bingbot/2.0', 'msnbot-203-0-113-10.search.msn.com'],
            ['203.0.113.11', 'YandexBot/3.0', 'spider-203-0-113-11.yandex.ru'],
            ['203.0.113.12', 'Baiduspider/2.0', 'baiduspider-203-0-113-12.crawl.baidu.com'],
            ['203.0.113.13', 'DuckDuckBot/1.1', 'host.duckduckgo.com'],
            ['203.0.113.14', 'Applebot/0.1', 'host.applebot.apple.com'],
            ['203.0.113.15', 'Mozilla/5.0 (compatible; Yahoo! Slurp)', 'host.crawl.yahoo.net'],
        ];
        foreach ($cases as [$ip, $ua, $host]) {
            $r = $this->resolver(['ptr:' . $ip => [$host . '.'], 'a:' . $host => [$ip]]);
            self::assertSame(CrawlerVerifier::VERIFIED, CrawlerVerifier::verify($ip, $ua, $r), "{$ua} must verify on {$host}");
        }
    }

    public function test_forward_mismatch_is_impersonator(): void
    {
        $r = $this->resolver(['ptr:1.2.3.4' => ['crawl.googlebot.com.'], 'a:crawl.googlebot.com' => ['9.9.9.9']]);
        self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify('1.2.3.4', 'Googlebot/2.1', $r));
    }

    public function test_offsuffix_ptr_is_impersonator(): void
    {
        $r = $this->resolver(['ptr:1.2.3.4' => ['evil.attacker.test.']]);
        self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify('1.2.3.4', 'bingbot/2.0', $r));
    }

    public function test_lookalike_suffix_cannot_bypass_the_dot_anchor(): void
    {
        // `evilgooglebot.com` must NOT satisfy `.googlebot.com` even if it forward-resolves to the IP.
        $r = $this->resolver(['ptr:1.2.3.4' => ['host.evilgooglebot.com.'], 'a:host.evilgooglebot.com' => ['1.2.3.4']]);
        self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify('1.2.3.4', 'Googlebot', $r));
    }

    public function test_absent_ptr_is_impersonator(): void
    {
        self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify('1.2.3.4', 'Googlebot', $this->resolver([])));
    }

    public function test_resolver_error_fails_closed(): void
    {
        $boom = static function (string $t, string $q): array { throw new RuntimeException('dns down'); };
        self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify('66.249.66.1', 'Googlebot', $boom));
    }

    public function test_private_and_reserved_ips_are_impersonator(): void
    {
        $r = $this->resolver(['ptr:10.0.0.5' => ['x.googlebot.com.'], 'a:x.googlebot.com' => ['10.0.0.5']]);
        foreach (['10.0.0.5', '192.168.1.1', '127.0.0.1', '169.254.0.1'] as $ip) {
            self::assertSame(CrawlerVerifier::IMPERSONATOR, CrawlerVerifier::verify($ip, 'Googlebot', $r), "{$ip} is not a global crawler IP");
        }
    }

    public function test_non_crawler_ua_is_not_claimed(): void
    {
        foreach (['Mozilla/5.0 (Windows NT 10.0) Chrome/120', 'curl/8.4.0', 'sqlmap/1.8', ''] as $ua) {
            self::assertSame(CrawlerVerifier::NOT_CLAIMED, CrawlerVerifier::verify('8.8.8.8', $ua, $this->resolver([])));
        }
    }

    public function test_ipv6_verifies_with_canonicalised_comparison(): void
    {
        $r = $this->resolver(['ptr:2001:4860:4801::1' => ['x.googlebot.com.'], 'aaaa:x.googlebot.com' => ['2001:4860:4801:0:0:0:0:1']]);
        self::assertSame(CrawlerVerifier::VERIFIED, CrawlerVerifier::verify('2001:4860:4801::1', 'Googlebot', $r));
    }

    public function test_multiple_ptr_names_one_valid_verifies(): void
    {
        $r = $this->resolver([
            'ptr:66.249.66.1' => ['stale.example.test.', 'crawl.googlebot.com.'],
            'a:crawl.googlebot.com' => ['66.249.66.1'],
        ]);
        self::assertSame(CrawlerVerifier::VERIFIED, CrawlerVerifier::verify('66.249.66.1', 'Googlebot', $r));
    }

    public function test_signal_flag_constants_exist(): void
    {
        self::assertSame('crawler_verified', BotSignalSet::CRAWLER_VERIFIED);
        self::assertSame('bot_impersonator', BotSignalSet::BOT_IMPERSONATOR);
        // The flags ride the generic flag map — a host sets them from the verify() verdict.
        $s = new BotSignalSet([BotSignalSet::BOT_IMPERSONATOR => true], 0, BotSignalSet::UA_GOOD_BOT);
        self::assertTrue($s->has(BotSignalSet::BOT_IMPERSONATOR));
        self::assertSame(BotSignalSet::UA_GOOD_BOT, $s->uaClass, 'the UA class stays the CLAIM; the flag carries the verdict');
    }
}
