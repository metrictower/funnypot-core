<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0237 — the honeytoken-retrieval seam tests (modeled on OastSeamTest). DecoySessionProbeTest
 * covers the matcher; this file proves the signal-only fold into classify(): a minted `s=1` cookie
 * folds a high-signal `honeytoken-retrieval` Detection without changing a single served byte, is
 * silent when no decoy-session key is configured, and bumps CLEAN -> SCANNER_PROBE only on a
 * null-handle miss.
 */
final class HoneytokenRetrievalSeamTest extends TestCase
{
    private const KEY = 'S3cr3t-Decoy-Signing-Key-must-never-leak';

    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    /** A classify-mode Config with the decoy-session key set (so the fold is armed). */
    private function keyedConfig(): Config
    {
        $c = new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0,
            false
        );
        $c->decoySessionKey = self::KEY;

        return $c;
    }

    /** The name=value cookie pair a browser sends back for the given payload class. */
    private function cookiePair(string $payload, string $name = 'phpMyAdmin'): string
    {
        $setCookie = (new Honeytoken(self::KEY))->cookie($name, $payload, '/phpmyadmin');
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    /**
     * Test #1: an s=1 cookie on a miss yields a high-signal, tagged, SCANNER_PROBE detection.
     */
    public function test_s1_cookie_yields_high_signal_detection_with_tag(): void
    {
        $engine = new Honeypot($this->store(), $this->keyedConfig());
        $r = new RequestContext('GET', '/nope', 'table=secrets', ['Cookie' => $this->cookiePair('s=1')]);
        $verdict = $engine->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched);
        self::assertContains('honeytoken-retrieval', $verdict->detection->tags());
        self::assertContains('decoy-session', $verdict->detection->tags());
        self::assertContains('breached-db', $verdict->detection->tags());
        self::assertContains('high-confidence', $verdict->detection->tags());
        self::assertSame('high', $verdict->detection->highestSeverity);
        self::assertSame('high', $verdict->severity);
        // A pure retrieval-only miss (null handle) is bumped CLEAN -> SCANNER_PROBE.
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    /**
     * Test #2: silent when no key is configured, and silent for a non-authenticated cookie (garbage /
     * s=0 / absent) even when the key is set.
     */
    public function test_no_fold_without_a_valid_authenticated_cookie(): void
    {
        // No decoy-session key configured: the seam is a no-op even with a real s=1 cookie.
        $unkeyed = new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0, false
        );
        $r = new RequestContext('GET', '/nope', '', ['Cookie' => $this->cookiePair('s=1')]);
        $verdict = (new Honeypot($this->store(), $unkeyed))->classify($r, SiteProfile::empty());
        self::assertNotContains('honeytoken-retrieval', $verdict->detection->tags());
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());

        // Key set, but the cookie is not an authenticated s=1: no fold.
        $engine = new Honeypot($this->store(), $this->keyedConfig());
        foreach ([null, 'phpMyAdmin=garbage', $this->cookiePair('s=0')] as $cookie) {
            $headers = $cookie === null ? [] : ['Cookie' => $cookie];
            $v = $engine->classify(new RequestContext('GET', '/nope', '', $headers), SiteProfile::empty());
            self::assertNotContains('honeytoken-retrieval', $v->detection->tags());
            self::assertSame(Verdict::CLEAN, $v->classification);
        }
    }

    /**
     * Test #3: served bytes read bundles, not the signal. A routed decoy served twice — once plain,
     * once with an s=1 cookie in the header — is byte-identical (status, body, headers modulo the
     * per-request X-Request-Id), while the retrieval run's detection carries honeytoken-retrieval and
     * the plain run's does not. Catches the fold leaking into the served response or altering gating.
     */
    public function test_honeytoken_fold_does_not_change_served_bytes(): void
    {
        $store = $this->servingStore();

        $plainSpy = $this->spy();
        $plain = (new Honeypot($store, $this->respondConfig(), $plainSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1'));

        $htSpy = $this->spy();
        $ht = (new Honeypot($store, $this->respondConfig(), $htSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1', ['Cookie' => $this->cookiePair('s=1')]));

        self::assertNotNull($plain);
        self::assertNotNull($ht);
        self::assertSame($plain->status, $ht->status);
        self::assertSame($plain->body, $ht->body);
        self::assertSame($this->headersSansRequestId($plain), $this->headersSansRequestId($ht));

        self::assertCount(1, $plainSpy->detections);
        self::assertCount(1, $htSpy->detections);
        self::assertNotContains('honeytoken-retrieval', $plainSpy->detections[0]->tags());
        self::assertContains('honeytoken-retrieval', $htSpy->detections[0]->tags());
    }

    /**
     * Test #4 (the CLEAN-with-route-handle seam): a root/homepage-class (sig=1) entry classifies CLEAN
     * with a route handle. An s=1 cookie must fold the signal WITHOUT bumping to SCANNER_PROBE
     * (fakeHandle is non-null, so the bump is gated off) — so serve-gating is untouched. Mirrors
     * OastSeamTest's equivalent guard against a fold that bumps all CLEAN verdicts.
     */
    public function test_fold_on_clean_root_handle_stays_clean(): void
    {
        $store = $this->rootHandleStore();
        $config = $this->keyedConfig();
        $engine = new Honeypot($store, $config);

        $plain = $engine->classify(new RequestContext('GET', '/home', 'a=1'), SiteProfile::empty());
        self::assertSame(Verdict::CLEAN, $plain->classification);
        self::assertNotNull($plain->fakeHandle);
        self::assertNotContains('honeytoken-retrieval', $plain->detection->tags());

        $ht = $engine->classify(
            new RequestContext('GET', '/home', 'a=1', ['Cookie' => $this->cookiePair('s=1')]),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::CLEAN, $ht->classification, 'a CLEAN entry WITH a handle must NOT bump to SCANNER_PROBE');
        self::assertNotNull($ht->fakeHandle, 'the handle must ride through untouched');
        self::assertContains('honeytoken-retrieval', $ht->detection->tags());
    }

    /**
     * Test #5 (structural no-callback / no-I/O): the fold body does only array/string work.
     */
    public function test_fold_source_has_no_network_primitive(): void
    {
        $needles = [
            'fsockopen', 'curl_', 'file_get_contents', 'fopen', 'stream_socket',
            'gethostby', 'dns_get_record', 'checkdnsrr', 'socket_create',
        ];
        $honeypot = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($honeypot);
        $start = strpos($honeypot, 'private function foldHoneytoken');
        self::assertNotFalse($start);
        $end = strpos($honeypot, 'private function', $start + 1);
        self::assertNotFalse($end, 'foldHoneytoken must not be the last private method (else the slice guard is vacuous)');
        $body = substr($honeypot, $start, $end - $start);
        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, $body, "foldHoneytoken must not reference {$needle}");
        }
    }

    // --- helpers -------------------------------------------------------------------------------

    private function rootHandleStore(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-root' => ['sev' => 'info', 'tags' => [], 'name' => 'Home'],
            ],
            'routes' => [
                'GET /home' => ['b' => [
                    ['s' => 200, 'bw' => ['HELLO'], 'nf' => [], 'h' => [], 'pid' => 'ph', 'sev' => 'info', 'sig' => 1, 't' => ['t-root']],
                ]],
            ],
        ]);
    }

    private function servingStore(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
                't-b' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'B'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['AAA'], 'nf' => [], 'h' => [], 'pid' => 'pa', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                    ['s' => 200, 'bw' => ['BBB'], 'nf' => [], 'h' => [], 'pid' => 'pb', 'sev' => 'low', 'sig' => 0, 't' => ['t-b']],
                ]],
            ],
        ]);
    }

    /** Respond mode, gate open, query-independent constant seed; decoy-session key set. */
    private function respondConfig(): Config
    {
        $c = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'seed-x'; },
            'coherent',
            \Funnypot\Core\Response\Style::MINIMAL,
            'high', 65536, 0, 0, false
        );
        $c->decoySessionKey = self::KEY;

        return $c;
    }

    /** @param SynthesizedResponse $resp @return array<string,string> */
    private function headersSansRequestId(SynthesizedResponse $resp): array
    {
        $h = $resp->headers;
        unset($h['X-Request-Id']);

        return $h;
    }

    private function spy(): Observer
    {
        return new class implements Observer {
            /** @var Detection[] */
            public $detections = [];
            /** @var string[] */
            public $outcomes = [];

            public function onDetection(RequestContext $r, Detection $d): void
            {
                $this->detections[] = $d;
            }

            public function shouldRespond(RequestContext $r, Detection $d): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void
            {
                $this->outcomes[] = $reason;
            }
        };
    }
}
