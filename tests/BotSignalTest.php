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

}
