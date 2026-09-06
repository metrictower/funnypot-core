<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\DecoySessionPayloads;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0237 — the honeytoken-retrieval seam tests (modeled on OastSeamTest). DecoySessionProbeTest
 * covers the matcher; this file proves the signal-only fold into classify(): a minted authenticated
 * cookie folds a high-signal `honeytoken-retrieval` Detection without changing a single served byte, is
 * silent when no decoy-session key is configured, and bumps CLEAN -> SCANNER_PROBE only on a
 * null-handle miss. The engine snapshots its deploy seed once, so a post-construction Config mutation
 * cannot split the probe identity from the mint identity (FP-0296).
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

    /** The name=value pair for an authenticated cookie minted at a config's snapshotted deploy seed. */
    private function authedCookie(Config $config, string $name = 'phpMyAdmin'): string
    {
        return $this->pairOf((new DecoySession(self::KEY, $config->deploySeed()))->mintCookie($name, '/phpmyadmin'));
    }

    /** The name=value pair for an authenticated cookie minted at a specific deploy seed. */
    private function authedCookieAtSeed(int $seed, string $name = 'phpMyAdmin'): string
    {
        return $this->pairOf((new DecoySession(self::KEY, $seed))->mintCookie($name, '/phpmyadmin'));
    }

    /** The name=value pair for a pre-auth marker at a config's snapshotted deploy seed. */
    private function preAuthCookie(Config $config, string $name = 'phpMyAdmin'): string
    {
        return $this->pairOf((new DecoySession(self::KEY, $config->deploySeed()))->preAuthCookie($name, '/phpmyadmin'));
    }

    /** The name=value pair for an arbitrary hand-signed payload (the retired literal token). */
    private function legacyCookie(string $payload = 's=1', string $name = 'phpMyAdmin'): string
    {
        return $this->pairOf((new Honeytoken(self::KEY))->cookie($name, $payload, '/phpmyadmin'));
    }

    private function pairOf(string $setCookie): string
    {
        $semi = strpos($setCookie, ';');

        return $semi === false ? $setCookie : substr($setCookie, 0, $semi);
    }

    /**
     * Test #1: an authenticated cookie on a miss yields a high-signal, tagged, SCANNER_PROBE detection.
     */
    public function test_authenticated_cookie_yields_high_signal_detection_with_tag(): void
    {
        $config = $this->keyedConfig();
        $engine = new Honeypot($this->store(), $config);
        $r = new RequestContext('GET', '/nope', 'table=secrets', ['Cookie' => $this->authedCookie($config)]);
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
     * Test #2: silent when no key is configured, and silent for a non-authenticated cookie (garbage,
     * pre-auth, legacy literal, a foreign deploy's authenticated token, absent) even when the key is set.
     */
    public function test_no_fold_without_a_valid_authenticated_cookie(): void
    {
        // No decoy-session key configured: the seam is a no-op even with a real authenticated cookie.
        $unkeyed = new Config(
            'detect', null, 'matched-only', null, 'coherent',
            \Funnypot\Core\Response\Style::MINIMAL, 'high', 65536, 0, 0, false
        );
        $r = new RequestContext('GET', '/nope', '', ['Cookie' => $this->authedCookie($unkeyed)]);
        $verdict = (new Honeypot($this->store(), $unkeyed))->classify($r, SiteProfile::empty());
        self::assertNotContains('honeytoken-retrieval', $verdict->detection->tags());
        self::assertSame(Verdict::CLEAN, $verdict->classification);
        self::assertTrue($verdict->detection->isEmpty());

        // Key set, but the cookie is not this deploy's authenticated value: no fold. Covers garbage, a
        // pre-auth marker, the retired literal `s=1`, and an authenticated token from a DIFFERENT seed.
        $config = $this->keyedConfig();
        $engine = new Honeypot($this->store(), $config);
        $foreignSeed = PersonaIdentity::seedFromMaterial('seam-foreign-deploy');
        self::assertNotSame(
            DecoySessionPayloads::authenticated($config->deploySeed()),
            DecoySessionPayloads::authenticated($foreignSeed),
            'the foreign seed must select a different pair or this case is vacuous'
        );
        foreach ([
            null,
            'phpMyAdmin=garbage',
            $this->preAuthCookie($config),
            $this->legacyCookie('s=1'),
            $this->authedCookieAtSeed($foreignSeed),
        ] as $cookie) {
            $headers = $cookie === null ? [] : ['Cookie' => $cookie];
            $v = $engine->classify(new RequestContext('GET', '/nope', '', $headers), SiteProfile::empty());
            self::assertNotContains('honeytoken-retrieval', $v->detection->tags());
            self::assertSame(Verdict::CLEAN, $v->classification);
        }
    }

    /**
     * Test #2b: the deploy seed is snapshotted at construction — mutating Config afterwards cannot split
     * the retrieval probe's identity from the mint identity the engine was built with. The engine keeps
     * folding the seed-A token and never folds a seed-B token, regardless of the post-construction field.
     */
    public function test_post_construction_config_mutation_cannot_split_probe_identity(): void
    {
        $config = $this->keyedConfig();
        $config->deploySeed = 'seam-deploy-A';
        $engine = new Honeypot($this->store(), $config);
        $seedA = PersonaIdentity::seedFromMaterial('seam-deploy-A');
        $seedB = PersonaIdentity::seedFromMaterial('seam-deploy-B');
        self::assertNotSame(
            DecoySessionPayloads::authenticated($seedA),
            DecoySessionPayloads::authenticated($seedB),
            'the two materials must select different pairs'
        );

        // Mutate the public identity field AFTER construction.
        $config->deploySeed = 'seam-deploy-B';

        // The engine still uses its snapshot (seed A): the seed-A token folds, the seed-B token does not.
        $vA = $engine->classify(
            new RequestContext('GET', '/nope', '', ['Cookie' => $this->authedCookieAtSeed($seedA)]),
            SiteProfile::empty()
        );
        self::assertContains('honeytoken-retrieval', $vA->detection->tags(), 'snapshot seed A still folds after mutation');

        $vB = $engine->classify(
            new RequestContext('GET', '/nope', '', ['Cookie' => $this->authedCookieAtSeed($seedB)]),
            SiteProfile::empty()
        );
        self::assertNotContains('honeytoken-retrieval', $vB->detection->tags(), 'the mutated (seed B) identity must not fold');
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
        $htConfig = $this->respondConfig();
        $ht = (new Honeypot($store, $htConfig, $htSpy))
            ->respond(new RequestContext('GET', '/multi', 'a=1', ['Cookie' => $this->authedCookie($htConfig)]));

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
     * with a route handle. An authenticated cookie must fold the signal WITHOUT bumping to SCANNER_PROBE
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
            new RequestContext('GET', '/home', 'a=1', ['Cookie' => $this->authedCookie($config)]),
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
