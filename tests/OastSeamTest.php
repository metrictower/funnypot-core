<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0175 — the OAST wiring (seam) tests. OastProbeTest covers the matcher; this file proves the
 * signal-only fold into classify()/respond(): a folded match becomes a high-signal Detection with
 * the oast-callback tag, without ever making a callback and without changing a single served byte.
 */
final class OastSeamTest extends TestCase
{
    /** The shipped compiled corpus (real routes + attack rules), as ClassifyTest uses it. */
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function engine(bool $attack = false): Honeypot
    {
        return new Honeypot($this->store(), new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0,
            $attack
        ));
    }

    /**
     * Test #1: an OAST payload in a param yields a high-signal, tagged, SCANNER_PROBE detection.
     * Catches the pre-plan state of the tree: OastProbe unwired into classify() (detection empty,
     * verdict CLEAN).
     */
    public function test_oast_payload_yields_high_signal_detection_with_tag(): void
    {
        $r = new RequestContext('GET', '/', 'url=http://x.oast.fun/');
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched);
        self::assertContains('oast-callback', $verdict->detection->tags());
        self::assertContains('interactsh', $verdict->detection->tags());
        self::assertSame('high', $verdict->detection->highestSeverity);
        self::assertSame('high', $verdict->severity);
        // A pure OAST-only miss (null handle) is bumped CLEAN -> SCANNER_PROBE.
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle);

        // The legacy detect() shim (classify against an empty profile) carries the same tag.
        self::assertContains('oast-callback', $this->engine()->detect($r)->tags());
    }

    /**
     * Test #1b: family label rides through as a tag (spot-check a second family + metadata SSRF).
     */
    public function test_oast_family_labels_ride_as_tags(): void
    {
        $meta = $this->engine()->classify(
            new RequestContext('GET', '/', 'url=http://169.254.169.254/latest/meta-data/'),
            SiteProfile::empty()
        );
        self::assertContains('oast-callback', $meta->detection->tags());
        self::assertContains('cloud-metadata', $meta->detection->tags());
        self::assertContains('ssrf', $meta->detection->tags());
        self::assertContains('oob', $meta->detection->tags());
    }

    /**
     * Test #2: false-positive guard — benign traffic to owasp.org / example.com / a roast.fun
     * near-miss raises NO oast-callback tag and stays CLEAN. Catches an over-broad match (a dropped
     * dot-prefix / \d{8,} guard) flagging legitimate traffic.
     */
    public function test_benign_domains_raise_no_oast_detection(): void
    {
        $cases = [
            new RequestContext('GET', '/', '', ['Referer' => 'https://owasp.org/www-project-zap/']),
            new RequestContext('GET', '/', 'next=https://example.com/dashboard'),
            new RequestContext('GET', '/', 'q=http://x.roast.fun/'),
        ];
        foreach ($cases as $r) {
            $verdict = $this->engine()->classify($r, SiteProfile::empty());
            self::assertNotContains('oast-callback', $verdict->detection->tags());
            self::assertSame(Verdict::CLEAN, $verdict->classification);
            self::assertTrue($verdict->detection->isEmpty());
        }
    }

    /**
     * Test #3 (signal-only invariant): an OAST-only spray under respond mode serves NOTHING (so
     * nothing that could be a callback) yet surfaces the signal to the Observer exactly once, and
     * never reports Outcome::SERVED. Catches a design that serves a decoy off an OAST-only probe,
     * or that fails to surface the signal on the no-serve path.
     */
    public function test_oast_only_never_serves_and_never_calls_back(): void
    {
        $spy = $this->spy();
        $engine = new Honeypot($this->store(), $this->respondConfig(), $spy);

        // A pure OAST/SSRF spray on an unrouted path: miss -> null handle -> SCANNER_PROBE.
        $resp = $engine->respond(new RequestContext('GET', '/nope', 'url=http://x.oast.fun/'));

        self::assertNull($resp, 'an OAST-only probe must serve nothing (no serve => no callback)');
        self::assertCount(1, $spy->detections, 'the signal must surface to onDetection exactly once');
        self::assertContains('oast-callback', $spy->detections[0]->tags());
        self::assertNotContains(Outcome::SERVED, $spy->outcomes, 'nothing may be served off an OAST-only probe');
    }

    /**
     * Test #3b: prove the no-callback invariant structurally — the detect path contains no
     * socket/DNS/fetch primitive. (OastProbe::detect + classify()'s foldOast are pure string work.)
     */
    public function test_detect_path_source_has_no_network_primitive(): void
    {
        $needles = [
            'fsockopen', 'curl_', 'file_get_contents', 'fopen', 'stream_socket',
            'gethostby', 'dns_get_record', 'checkdnsrr', 'socket_create',
        ];
        $oast = file_get_contents(__DIR__ . '/../src/OastProbe.php');
        self::assertNotFalse($oast);
        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, $oast, "OastProbe must not reference {$needle}");
        }
        // The fold itself (classify/foldOast) does only array/string work — assert the fold body.
        $honeypot = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($honeypot);
        $start = strpos($honeypot, 'private function foldOast');
        self::assertNotFalse($start);
        $end = strpos($honeypot, 'private function', $start + 1);
        $body = substr($honeypot, $start, $end - $start);
        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, $body, "foldOast must not reference {$needle}");
        }
    }

    /**
     * Test #4 (SHOULD-FIX): serving reads bundles, not the signal. A routed decoy served twice —
     * once plain, once with an OAST param appended to the QUERY only (host-based/constant seed
     * unchanged) — is byte-identical (status, body, headers modulo the per-request X-Request-Id),
     * while the OAST run's detection carries oast-callback and the plain run's does not. Catches the
     * fold leaking the tag/severity into the served response or altering serve-gating.
     */
    public function test_oast_fold_does_not_change_served_bytes(): void
    {
        $store = $this->servingStore();

        $plainSpy = $this->spy();
        $plain = (new Honeypot($store, $this->respondConfig(), $plainSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1'));

        $oastSpy = $this->spy();
        // OAST string appended to the QUERY only — never the path (would change route resolution) —
        // and the seed is a query-independent constant, so both runs pick the same persona.
        $oast = (new Honeypot($store, $this->respondConfig(), $oastSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1&x=http://y.oast.fun/'));

        self::assertNotNull($plain);
        self::assertNotNull($oast);
        self::assertSame($plain->status, $oast->status);
        self::assertSame($plain->body, $oast->body);
        self::assertSame($this->headersSansRequestId($plain), $this->headersSansRequestId($oast));

        // ...yet the signal differs: the OAST run carries the tag, the plain run does not.
        self::assertNotContains('oast-callback', $plainSpy->detections[0]->tags());
        self::assertContains('oast-callback', $oastSpy->detections[0]->tags());
    }

    /**
     * Test #5 (refactor regression): classify() is byte-identical when no OAST zone is present, for
     * a benign miss, a routed probe, and an attack-class payload. Catches the
     * classify()->classifyContent() extraction changing any existing verdict.
     */
    public function test_classify_byte_identical_when_no_oast(): void
    {
        // Benign miss.
        $clean = $this->engine()->classify(new RequestContext('GET', '/totally/legit/page'), SiteProfile::empty());
        self::assertSame([
            'classification' => Verdict::CLEAN,
            'templateIds' => [],
            'tags' => [],
            'severity' => '',
            'fakeHandle' => null,
        ], $this->shape($clean));

        // Routed probe.
        $probe = $this->engine()->classify(new RequestContext('GET', '/.git/config'), SiteProfile::empty());
        self::assertSame([
            'classification' => Verdict::SCANNER_PROBE,
            'templateIds' => ['git-config'],
            'tags' => ['config', 'git', 'exposure', 'vuln'],
            'severity' => 'medium',
            'fakeHandle' => 'GET /.git/config',
        ], $this->shape($probe));
        self::assertNotContains('oast-callback', $probe->detection->tags());

        // Attack-class payload (LFI) on an unrouted path with attack emulation on.
        $attack = $this->engine(true)->classify(
            new RequestContext('GET', '/nope', 'file=../../../../etc/passwd'),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::ATTACK_CLASS, $attack->classification);
        self::assertSame(['attack-lfi-unix'], $attack->detection->templateIds());
        self::assertNotContains('oast-callback', $attack->detection->tags());
        self::assertNotNull($attack->fakeHandle);
        self::assertSame(FakeHandle::KIND_ATTACK, $attack->fakeHandle->kind);
    }

    // --- helpers -------------------------------------------------------------------------------

    /** @return array<string,mixed> the load-bearing fields of a Verdict, for equality. */
    private function shape(Verdict $v): array
    {
        return [
            'classification' => $v->classification,
            'templateIds' => $v->detection->templateIds(),
            'tags' => $v->detection->tags(),
            'severity' => $v->severity,
            'fakeHandle' => $v->fakeHandle === null ? null : $v->fakeHandle->key,
        ];
    }

    /** A multi-bundle route that reliably serves in respond mode (per GatingTest). */
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

    /** Respond mode, gate open, query-independent constant seed (so persona is query-stable). */
    private function respondConfig(): Config
    {
        return new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'seed-x'; },
            'coherent',
            \Funnypot\Core\Response\Style::MINIMAL,
            'high', 65536, 0, 0, false
        );
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
