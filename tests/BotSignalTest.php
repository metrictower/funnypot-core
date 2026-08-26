<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\BotSignalSet;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Phase 1b (decision S / design §2.4): classify() computes the request-shape bot signals into
 * Verdict.signals + anomaly. Pure computation, no I/O, no action — each signal is a MODIFIER
 * that raises anomaly; a signals-only request stays `clean` (the composite call is the policy's).
 * No version-age detection. INPUT-side only — nothing computed here is ever emitted.
 */
final class BotSignalTest extends TestCase
{
    private function engine(): Honeypot
    {
        return new Honeypot(new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php'));
    }

    private function signals(array $headers, string $path = '/totally/legit/page', string $httpVersion = ''): BotSignalSet
    {
        $r = new RequestContext('GET', $path, '', $headers, null, 'host', 'https', $httpVersion);

        return $this->engine()->classify($r, SiteProfile::empty())->signals;
    }

    /** A modern-Chrome header set that fires no signal (weight 0). */
    private function browser(array $overrides = []): array
    {
        $base = [
            'Host' => 'host',
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept' => 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language' => 'en-US,en;q=0.9',
            'Accept-Encoding' => 'gzip, deflate, br',
            'Sec-Fetch-Site' => 'none',
            'Sec-Fetch-Mode' => 'navigate',
            'Sec-Fetch-User' => '?1',
            'Sec-Fetch-Dest' => 'document',
            'Sec-Ch-Ua' => '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            'Sec-Ch-Ua-Mobile' => '?0',
            'Sec-Ch-Ua-Platform' => '"Windows"',
        ];

        foreach ($overrides as $k => $v) {
            if ($v === null) {
                unset($base[$k]);
            } else {
                $base[$k] = $v;
            }
        }

        return $base;
    }

    public function test_header_presence_weights_accrue_exactly(): void
    {
        $s = $this->signals([]); // header-less request

        self::assertTrue($s->has(BotSignalSet::MISSING_ACCEPT));
        self::assertTrue($s->has(BotSignalSet::MISSING_ACCEPT_LANGUAGE));
        self::assertTrue($s->has(BotSignalSet::MISSING_ACCEPT_ENCODING));
        self::assertTrue($s->has(BotSignalSet::EMPTY_USER_AGENT));
        self::assertTrue($s->has(BotSignalSet::MISSING_FETCH_METADATA));
        self::assertTrue($s->has(BotSignalSet::MISSING_CLIENT_HINTS));
        self::assertSame(BotSignalSet::UA_EMPTY, $s->uaClass);
        // 5 + 5 + 5 + 10 (presence) + 2 + 2 (fetch/hint absence)
        self::assertSame(29, $s->weight);
    }

    public function test_modern_browser_fires_no_signal(): void
    {
        $s = $this->signals($this->browser());

        self::assertSame(0, $s->weight);
        self::assertFalse($s->anyFired());
        self::assertSame(BotSignalSet::UA_BROWSER, $s->uaClass);
    }

    public function test_old_but_legit_browser_is_not_penalised_on_version_age(): void
    {
        // Same headers, an old Chrome version. No version-age detection => identical treatment.
        $old = $this->browser([
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
            'Sec-Ch-Ua' => '"Chromium";v="72", "Google Chrome";v="72"',
        ]);

        $s = $this->signals($old);
        self::assertSame(0, $s->weight);
        self::assertFalse($s->anyFired());
    }

    public function test_accept_wildcard_from_browser_is_a_contradiction(): void
    {
        $s = $this->signals($this->browser(['Accept' => '*/*']));

        self::assertTrue($s->has(BotSignalSet::ACCEPT_WILDCARD_FROM_BROWSER));
        self::assertSame(10, $s->weight);
    }

    public function test_chromium_ua_without_hints_or_fetch_metadata_contradicts(): void
    {
        $s = $this->signals($this->browser([
            'Sec-Fetch-Site' => null,
            'Sec-Fetch-Mode' => null,
            'Sec-Fetch-User' => null,
            'Sec-Fetch-Dest' => null,
            'Sec-Ch-Ua' => null,
            'Sec-Ch-Ua-Mobile' => null,
            'Sec-Ch-Ua-Platform' => null,
        ]));

        self::assertTrue($s->has(BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS));
        self::assertTrue($s->has(BotSignalSet::MISSING_FETCH_METADATA));
        self::assertTrue($s->has(BotSignalSet::MISSING_CLIENT_HINTS));
        // 15 (contradiction) + 2 + 2 (absences)
        self::assertSame(19, $s->weight);
    }

    public function test_http2_with_forbidden_connection_header(): void
    {
        // Baseline over h2 with no Connection header fires nothing...
        self::assertSame(0, $this->signals($this->browser(), '/totally/legit/page', '2')->weight);
        // ...adding a Connection header on h2 is a protocol contradiction.
        $s = $this->signals($this->browser(['Connection' => 'keep-alive']), '/totally/legit/page', '2');
        self::assertTrue($s->has(BotSignalSet::H2_FORBIDDEN_CONNECTION));
        self::assertSame(15, $s->weight);
    }

    public function test_accept_encoding_without_gzip(): void
    {
        $s = $this->signals($this->browser(['Accept-Encoding' => 'br, deflate']));

        self::assertTrue($s->has(BotSignalSet::ACCEPT_ENCODING_NO_GZIP));
        self::assertSame(5, $s->weight);
    }

    public function test_ua_os_versus_platform_hint_mismatch(): void
    {
        $s = $this->signals($this->browser(['Sec-Ch-Ua-Platform' => '"Linux"']));

        self::assertTrue($s->has(BotSignalSet::UA_PLATFORM_MISMATCH));
        self::assertSame(10, $s->weight);
    }

    public function test_scanner_user_agent_is_classified_and_flagged(): void
    {
        $s = $this->signals(['User-Agent' => 'sqlmap/1.5.2#stable (http://sqlmap.org)']);

        self::assertSame(BotSignalSet::UA_SCANNER, $s->uaClass);
        self::assertTrue($s->has(BotSignalSet::SCANNER_USER_AGENT));
    }

    public function test_script_clients_are_classified(): void
    {
        self::assertSame(BotSignalSet::UA_SCRIPT, $this->signals(['User-Agent' => 'curl/7.68.0'])->uaClass);
        self::assertSame(BotSignalSet::UA_SCRIPT, $this->signals(['User-Agent' => 'python-requests/2.25.1'])->uaClass);
        self::assertSame(BotSignalSet::UA_SCRIPT, $this->signals(['User-Agent' => 'Go-http-client/2.0'])->uaClass);
    }

    public function test_fingerprint_is_stable_across_version_bump_and_list_reorder(): void
    {
        $v120 = $this->signals($this->browser())->fingerprint;
        $v121 = $this->signals($this->browser([
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Sec-Ch-Ua' => '"Not_A Brand";v="8", "Chromium";v="121", "Google Chrome";v="121"',
        ]))->fingerprint;
        $reordered = $this->signals($this->browser(['Accept-Encoding' => 'br, gzip, deflate']))->fingerprint;

        self::assertSame($v120, $v121, 'a Chromium version bump must not change the fingerprint');
        self::assertSame($v120, $reordered, 'reordering a list-header must not change the fingerprint');
    }

    public function test_fingerprint_distinguishes_client_families(): void
    {
        $curl = $this->signals(['Host' => 'h', 'User-Agent' => 'curl/7.68.0', 'Accept' => '*/*'])->fingerprint;
        $python = $this->signals(['Host' => 'h', 'User-Agent' => 'python-requests/2.25.1', 'Accept-Encoding' => 'gzip, deflate', 'Accept' => '*/*', 'Connection' => 'keep-alive'])->fingerprint;
        $browser = $this->signals($this->browser())->fingerprint;

        self::assertNotSame($curl, $python);
        self::assertNotSame($curl, $browser);
        self::assertNotSame($python, $browser);
    }

    public function test_signals_only_request_stays_clean_with_nonzero_anomaly(): void
    {
        // A request that fires only bot signals (no route, no attack) classifies clean — the
        // composite bot decision is the policy's (S2/S3) — but carries the anomaly + signals.
        $r = new RequestContext('GET', '/totally/legit/page', '', ['User-Agent' => 'curl/7.68.0']);
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertGreaterThan(0, $verdict->anomaly);
        self::assertSame($verdict->signals->weight, $verdict->anomaly);
        self::assertTrue($verdict->signals->anyFired());
    }

    public function test_signals_are_input_side_only_and_never_emitted(): void
    {
        // Fire signals AND route to a probe, then serve. No signal flag name or the fingerprint
        // value may appear anywhere in the response (invariant #1 / fingerprint-safety).
        $engine = new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php'),
            new Config('respond', static function (RequestContext $r): bool { return true; })
        );
        $r = new RequestContext('GET', '/.git/config', '', ['User-Agent' => 'sqlmap/1.5.2']);

        $verdict = $engine->classify($r, SiteProfile::empty());
        self::assertTrue($verdict->signals->anyFired());

        $response = $engine->respond($r);
        self::assertNotNull($response);

        $haystack = $response->body . ' ' . implode(' ', array_keys($response->headers)) . ' ' . implode(' ', $response->headers);
        foreach (array_keys($verdict->signals->flags) as $flagName) {
            self::assertStringNotContainsString($flagName, $haystack, "signal flag {$flagName} leaked into the response");
        }
        self::assertStringNotContainsString($verdict->signals->fingerprint, $haystack);
        self::assertNotSame('', $verdict->signals->fingerprint);
    }

    // ── FP-0096: a non-navigation must not be scored for headers a navigation sends ──

    /**
     * A genuine XHR from a real browser. Chrome omits Accept-Language on fetch/XHR, so scoring
     * header absence unconditionally charged every AJAX call on a JS-heavy site.
     */
    public function test_xhr_from_a_real_browser_scores_zero(): void
    {
        $set = $this->signals($this->browser([
            'Accept' => 'application/json',
            'Accept-Language' => null,
            'X-Requested-With' => 'XMLHttpRequest',
            'Sec-Fetch-Mode' => 'cors',
            'Sec-Fetch-Dest' => 'empty',
            'Sec-Fetch-User' => null,
        ]), '/api/data');

        self::assertSame(0, $set->weight, 'a genuine XHR is not anomalous');
    }

    /** fetch() defaults to Accept: */ /* — normal for a non-navigation, suspicious only for one. */
    public function test_fetch_with_wildcard_accept_scores_zero(): void
    {
        $set = $this->signals($this->browser([
            'Accept' => '*/*',
            'Accept-Language' => null,
            'Sec-Fetch-Mode' => 'cors',
            'Sec-Fetch-Dest' => 'empty',
            'Sec-Fetch-User' => null,
        ]), '/api/data');

        self::assertSame(0, $set->weight);
        self::assertFalse($set->has(BotSignalSet::ACCEPT_WILDCARD_FROM_BROWSER));
    }

    /** The suppression is scoped to non-navigations: a navigation is scored exactly as before. */
    public function test_a_navigation_missing_accept_language_still_scores(): void
    {
        $set = $this->signals($this->browser(['Accept-Language' => null]));

        self::assertTrue($set->has(BotSignalSet::MISSING_ACCEPT_LANGUAGE));
        self::assertSame(5, $set->weight);
    }

    /** Claiming cors must not launder a scanner past the signals that matter. */
    public function test_faking_cors_does_not_suppress_the_scanner_signal(): void
    {
        $set = $this->signals([
            'Host' => 'host',
            'User-Agent' => 'sqlmap/1.7',
            'Sec-Fetch-Mode' => 'cors',
        ], '/api/data');

        self::assertTrue($set->has(BotSignalSet::SCANNER_USER_AGENT), 'scanner UA is never suppressed');
        self::assertGreaterThanOrEqual(20, $set->weight);
    }

    /** An empty UA is about the client, not the request kind — never suppressed. */
    public function test_faking_cors_does_not_suppress_an_empty_user_agent(): void
    {
        $set = $this->signals([
            'Host' => 'host',
            'Sec-Fetch-Mode' => 'cors',
        ], '/api/data');

        self::assertTrue($set->has(BotSignalSet::EMPTY_USER_AGENT));
    }


    // ── FP-0095: a legitimate crawler is not merely "not a scanner" ──

    /** @return array<string,string> */
    private function crawler(string $ua): array
    {
        return array('Host' => 'host', 'User-Agent' => $ua, 'Accept' => 'text/html');
    }

    public function test_known_good_bots_are_classified_as_such(): void
    {
        $uas = array(
            'Googlebot' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Googlebot-mobile' => 'Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36 (KHTML, like Gecko) '
                . 'Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Bingbot' => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Baiduspider' => 'Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)',
            'YandexBot' => 'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            'DuckDuckBot' => 'DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)',
            'Slurp' => 'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
            'facebookexternalhit' => 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
        );

        foreach ($uas as $name => $ua) {
            self::assertSame(
                BotSignalSet::UA_GOOD_BOT,
                $this->signals($this->crawler($ua))->uaClass,
                $name . ' is a legitimate crawler'
            );
        }
    }

    /**
     * Weight 0 means weight 0 in both directions: the class must not buy a discount either.
     * A crawler word appended to a Chromium-claiming UA is the cheapest laundering attempt there
     * is, so every recognised token is pinned at a delta of exactly zero.
     */
    public function test_appending_a_crawler_token_to_a_chrome_ua_changes_nothing(): void
    {
        $chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $tokens = array(
            'Googlebot', 'bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider', 'YandexBot', 'Applebot',
            'facebookexternalhit', 'Twitterbot', 'LinkedInBot', 'Pinterest', 'Discordbot',
            'TelegramBot', 'WhatsApp', 'Slackbot', 'RedditBot', 'PetalBot', 'SeznamBot',
        );

        $plain = $this->signals($this->crawler($chrome))->weight;

        foreach ($tokens as $token) {
            $laundered = $this->signals($this->crawler($chrome . ' ' . $token));

            self::assertSame(BotSignalSet::UA_GOOD_BOT, $laundered->uaClass, $token . ' is claimed');
            self::assertSame($plain, $laundered->weight, 'claiming ' . $token . ' must buy nothing');
        }
    }

    /** Still no weight of its own: an honest crawler UA scores as any other non-browser client. */
    public function test_a_good_bot_adds_no_anomaly_weight_of_its_own(): void
    {
        $googlebot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        $unknown = 'SomeCrawler/1.0';

        $good = $this->signals($this->crawler($googlebot));
        $unk = $this->signals($this->crawler($unknown));

        self::assertSame(BotSignalSet::UA_GOOD_BOT, $good->uaClass);
        self::assertSame($unk->weight, $good->weight, 'the class itself carries no weight');
    }

    /** A scanner claiming to be Googlebot is a scanner. Order matters. */
    public function test_a_scanner_claiming_to_be_googlebot_is_still_a_scanner(): void
    {
        $set = $this->signals($this->crawler('sqlmap/1.7 (compatible; Googlebot/2.1)'));

        self::assertSame(BotSignalSet::UA_SCANNER, $set->uaClass);
        self::assertTrue($set->has(BotSignalSet::SCANNER_USER_AGENT));
    }

    /** Tooling is its own thing — never folded into the good-bot class. */
    public function test_tooling_is_not_a_good_bot(): void
    {
        foreach (array('Postman/7.36', 'HTTPie/3.2.1', 'Scrapy/2.11 (+https://scrapy.org)') as $ua) {
            self::assertNotSame(
                BotSignalSet::UA_GOOD_BOT,
                $this->signals($this->crawler($ua))->uaClass,
                $ua . ' is tooling, not a legitimate crawler'
            );
        }
    }

    /** A real browser is unaffected. */
    public function test_a_browser_is_still_a_browser(): void
    {
        self::assertSame(BotSignalSet::UA_BROWSER, $this->signals($this->browser())->uaClass);
    }

    /** The browser test is the `Mozilla/` prefix — the word alone, anywhere, proves nothing. */
    public function test_a_ua_merely_containing_mozilla_is_not_a_browser(): void
    {
        foreach (array('EvilTool (mozilla)', 'mozilla-ish-scanner') as $ua) {
            self::assertSame(
                BotSignalSet::UA_UNKNOWN,
                $this->signals($this->crawler($ua))->uaClass,
                $ua . ' does not start with Mozilla/'
            );
        }
    }


    /**
     * Googlebot's mobile UA contains "Chrome" and sends no client hints, so it fires the
     * contradiction — and must keep firing. The claim is an unverified string; a host that has
     * confirmed the crawler by reverse DNS is the one entitled to forgive the signal.
     */
    public function test_a_good_bot_claim_does_not_suppress_the_browser_contradiction(): void
    {
        $mobile = 'Mozilla/5.0 (Linux; Android 6.0.1) AppleWebKit/537.36 (KHTML, like Gecko) '
            . 'Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';

        $set = $this->signals($this->crawler($mobile));

        self::assertSame(BotSignalSet::UA_GOOD_BOT, $set->uaClass);
        self::assertTrue($set->has(BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS));
    }

    /** But a real Chrome UA with no hints and no fetch metadata still contradicts itself. */
    public function test_a_hintless_chrome_claim_still_fires_for_a_non_crawler(): void
    {
        $set = $this->signals(array(
            'Host' => 'host',
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
            'Accept' => 'text/html',
        ));

        self::assertTrue($set->has(BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS));
    }


    // ── FP-0096 review fixes: the suppression must not be a laundering primitive ──

    /** An unrecognised sec-fetch-mode is odd in itself, and must NOT earn the suppression. */
    public function test_an_unknown_fetch_mode_is_treated_as_a_navigation(): void
    {
        $bare = array('Host' => 'host', 'User-Agent' => 'sqlmap/1.7');

        $absent = $this->signals($bare)->weight;
        $garbage = $this->signals($bare + array('Sec-Fetch-Mode' => 'banana'))->weight;
        $cors = $this->signals($bare + array('Sec-Fetch-Mode' => 'cors'))->weight;

        self::assertSame($absent, $garbage, 'an unknown value must score as a navigation');
        self::assertLessThan($garbage, $cors, 'only a recognised subresource mode suppresses');
    }

    /**
     * Accept-Encoding is a forbidden header name — the browser sets it on fetch/XHR exactly as on
     * a navigation, so its absence is never legitimate and must not be suppressed.
     */
    public function test_missing_accept_encoding_fires_on_a_subresource_too(): void
    {
        $set = $this->signals($this->browser(array(
            'Accept' => 'application/json',
            'Accept-Encoding' => null,
            'Sec-Fetch-Mode' => 'cors',
            'Sec-Fetch-Dest' => 'empty',
        )), '/api/data');

        self::assertTrue($set->has(BotSignalSet::MISSING_ACCEPT_ENCODING));
    }

    /**
     * One forged header must not disarm the client-hint contradiction. A real browser sends
     * sec-fetch-site, -mode and -dest together, so the trio is what counts as fetch metadata.
     */
    public function test_a_lone_forged_fetch_mode_does_not_disarm_the_contradiction(): void
    {
        $chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            . '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

        $set = $this->signals(array(
            'Host' => 'host',
            'User-Agent' => $chrome,
            'Sec-Fetch-Mode' => 'cors',
        ));

        self::assertTrue(
            $set->has(BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS),
            'claiming Chrome with no client hints is still a contradiction'
        );
    }

    /** The laundering budget, pinned: one forged header may buy Accept-Language and no more. */
    public function test_forging_a_subresource_mode_launders_at_most_five_points(): void
    {
        $bare = array('Host' => 'host', 'User-Agent' => 'sqlmap/1.7');

        $honest = $this->signals($bare)->weight;
        $forged = $this->signals($bare + array('Sec-Fetch-Mode' => 'cors'))->weight;

        self::assertSame(5, $honest - $forged, 'only MISSING_ACCEPT_LANGUAGE may be suppressed');
    }

}
