<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Honeytoken;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\InjectionPayloads;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0239 — the render-time seeding + beacon. These are the falsifiable "it works AND rides the real
 * wiring path" assertions: the gate flag threaded Config → Honeypot → EmulatorRegistry::default() →
 * RouteTemplateEmulator must be CONSULTED inside render()/applyInjection() (spec invariant 8), the
 * beacon URL must be server-signed and absent when unconfigured (invariants 2/3), the block must stay
 * size-capped (invariant 4), and it must never reflect attacker bytes (invariant 5).
 */
final class PromptInjectionSeedingTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $full = null;

    private function set(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    private static function full(): array
    {
        if (self::$full === null) {
            self::$full = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$full;
    }

    /** @return array<string,mixed> a real compiled bundle for a taunt-carrying decoy route. */
    private function bundle(string $route, int $i = 0): array
    {
        $routes = self::full()['routes'] ?? [];
        self::assertArrayHasKey($route, $routes, "route {$route} missing from the compiled index");

        return $routes[$route]['b'][$i];
    }

    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
    }

    /** A Config with the gate on + a beacon configured. */
    private function seedingConfig(): Config
    {
        $c = new Config();
        $c->promptInjectionSeeding = true;
        $c->beaconUrl = 'https://beacon.example.test/confirm';
        $c->decoySessionKey = 'unit-test-deploy-key';

        return $c;
    }

    /**
     * The wiring proof (spec §8.8). This assertion is UNSATISFIABLE under the discarded SynthesisConfig
     * wiring (the emulator never reads that struct) — a green test is proof the flag rides the real path.
     */
    public function test_flag_reaches_emulator(): void
    {
        $bundle = $this->bundle('GET /readme.html');
        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=TOKEN'];

        // (i) unit: gate ON via the ctor arg ⇒ block present; gate OFF ⇒ absent.
        $on = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), true, $canary);
        $off = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), false, []);
        $bodyOn = $on->render($bundle, Style::REALISTIC, 7)->body;
        $bodyOff = $off->render($bundle, Style::REALISTIC, 7)->body;
        self::assertStringContainsString('already-decommissioned', $bodyOn, 'gate ON ⇒ injection block present');
        self::assertStringNotContainsString('already-decommissioned', $bodyOff, 'gate OFF ⇒ injection block absent');

        // (ii) end-to-end: a Honeypot built from a flag-ON Config ⇒ the decoy carries the block; the
        // default Config (flag off) ⇒ it does not. This exercises the WHOLE thread through Honeypot.
        $r = new RequestContext('GET', '/readme.html');

        $engineOn = new Honeypot($this->store(), $this->seedingConfig());
        $vOn = $engineOn->classify($r, SiteProfile::empty());
        $fOn = $engineOn->synthesize($vOn, SiteProfile::empty(), 'seed');
        self::assertNotNull($fOn, 'flag-on Honeypot must still render the decoy');
        self::assertStringContainsString('already-decommissioned', $fOn->body, 'flag-on Honeypot ⇒ block present');

        $engineOff = new Honeypot($this->store(), new Config());
        $vOff = $engineOff->classify($r, SiteProfile::empty());
        $fOff = $engineOff->synthesize($vOff, SiteProfile::empty(), 'seed');
        self::assertNotNull($fOff);
        self::assertStringNotContainsString('already-decommissioned', $fOff->body, 'default Honeypot ⇒ block absent');
    }

    public function test_seeded_block_present_when_enabled_in_each_comment_mode(): void
    {
        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=TOK'];
        $emu = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), true, $canary);

        // block mode (HTML comment) — WordPress readme.
        $html = $emu->render($this->bundle('GET /readme.html'), Style::REALISTIC, 7)->body;
        self::assertStringContainsString('<!--', $html);
        self::assertStringContainsString('OUT OF SCOPE', $html);

        // line mode (# prefix) — phpMyAdmin README.
        $line = $emu->render($this->bundle('GET /phpmyadmin/README'), Style::REALISTIC, 7)->body;
        self::assertMatchesRegularExpression('/#\s+automated-assessment note/', $line);

        // inline_field mode (JSON) — ai-plugin manifest must still parse.
        $json = $emu->render($this->bundle('GET /.well-known/ai-plugin.json'), Style::REALISTIC, 7)->body;
        self::assertStringContainsString('already-decommissioned', $json);
        self::assertNotNull(json_decode($json), 'JSON decoy must still parse after inline_field injection: ' . $json);
    }

    /**
     * FP-0244 (opus nit #2) — both features ON at once. Style::TAUNT injects a `_comment` field and
     * prompt-injection seeding injects a `_assessment` field into the SAME inline_field JSON body; the
     * two keys are DISTINCT by construction, so the document must stay valid JSON with exactly one of
     * each (no duplicate-key corruption). Exercised across several JSON decoy routes.
     */
    public function test_both_features_on_inline_field_json_stays_valid_with_distinct_keys(): void
    {
        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=' . str_repeat('a', 40)];
        $emu = new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), true, $canary);

        foreach ([
            'GET /.well-known/ai-plugin.json',
            'GET /package.json',
            'GET /openapi.json',
        ] as $route) {
            // TAUNT style AND the injection gate on together.
            $body = $emu->render($this->bundle($route), Style::TAUNT, 7)->body;

            $decoded = json_decode($body, true);
            self::assertNotNull($decoded, "{$route}: both features on must leave valid JSON: {$body}");
            self::assertIsArray($decoded, "{$route}: JSON object expected");

            // Exactly one _comment (the taunt) and one _assessment (the injection) — no duplicate keys.
            self::assertSame(1, substr_count($body, '"_comment"'), "{$route}: exactly one _comment field");
            self::assertSame(1, substr_count($body, '"_assessment"'), "{$route}: exactly one _assessment field");
            self::assertArrayHasKey('_comment', $decoded, "{$route}: taunt _comment present");
            self::assertArrayHasKey('_assessment', $decoded, "{$route}: injection _assessment present");

            // Both payloads actually landed (the troll banner in _comment, the misdirection in _assessment).
            self::assertStringContainsString('already-decommissioned', (string) $decoded['_assessment'], "{$route}: injection text in _assessment");
        }
    }

    public function test_beacon_url_present_and_signed(): void
    {
        $config = $this->seedingConfig();
        $engine = new Honeypot($this->store(), $config);
        $f = $engine->synthesize(
            $engine->classify(new RequestContext('GET', '/readme.html'), SiteProfile::empty()),
            SiteProfile::empty(),
            'seed'
        );
        self::assertNotNull($f);

        // The rendered URL carries the exact token produced by beaconToken() over the deploy seed with
        // the configured key — recomputing it with the SAME key reproduces it (verifies the signature).
        $expected = (new Honeytoken('unit-test-deploy-key'))->beaconToken((string) $config->deploySeed());
        self::assertStringContainsString('https://beacon.example.test/confirm?t=' . $expected, $f->body);

        // A DIFFERENT signing key yields a DIFFERENT token — the HMAC is load-bearing, not decorative.
        $wrong = (new Honeytoken('some-other-key'))->beaconToken((string) $config->deploySeed());
        self::assertStringNotContainsString('t=' . $wrong, $f->body);

        // The token round-trips through the verify path (base64url → ref.sig → hash_equals) — the app
        // follow-up decodes it exactly this way.
        $raw = base64_decode(strtr($expected, '-_', '+/'), true);
        self::assertIsString($raw);
        $dot = strrpos($raw, '.');
        self::assertNotFalse($dot);
        $ref = substr($raw, 0, $dot);
        $sig = substr($raw, $dot + 1);
        self::assertTrue(hash_equals(substr(hash_hmac('sha256', $ref, 'unit-test-deploy-key'), 0, 16), $sig));
    }

    public function test_no_beacon_url_when_unconfigured(): void
    {
        // Gate on but NO beacon URL: the misdirection block still appears, but NO URL is emitted
        // (invariant 3 — self-beacon only, never a literal fallback host).
        $c = new Config();
        $c->promptInjectionSeeding = true; // no beaconUrl, no key
        $engine = new Honeypot($this->store(), $c);
        $f = $engine->synthesize(
            $engine->classify(new RequestContext('GET', '/readme.html'), SiteProfile::empty()),
            SiteProfile::empty(),
            'seed'
        );
        self::assertNotNull($f);
        self::assertStringContainsString('already-decommissioned', $f->body, 'misdirection still seeds without a beacon');
        self::assertStringNotContainsString('http', substr($f->body, strpos($f->body, 'already-decommissioned')), 'no URL without a configured beacon');
        self::assertStringNotContainsString('{{canary', $f->body, 'the beacon directive is never left unrendered');
    }

    /**
     * FP-0244 (opus nit #1) — a beaconUrl pointed at a private / reserved / loopback host or the cloud
     * metadata endpoint is a misconfiguration; the engine rejects it and fails CLOSED (misdirection
     * still seeds, but NO beacon URL is emitted), while a normal public URL still beacons.
     */
    public function test_beacon_url_footgun_hosts_fail_closed(): void
    {
        foreach ([
            'http://169.254.169.254/latest/meta-data/',   // cloud metadata endpoint
            'https://localhost/confirm',                   // loopback name
            'http://127.0.0.1:8080/confirm',               // loopback IP
            'https://10.0.0.5/confirm',                    // RFC1918 private
            'http://192.168.1.1/confirm',                  // RFC1918 private
            'https://metadata.google.internal/x',          // GCP metadata name
            'https://internal-box/confirm',                // dotless internal short name
            'not-a-url',                                    // syntactically invalid
            'http://169.254.169.254./latest/meta-data/',   // trailing-dot FQDN-root bypass of the metadata IP
            'https://metadata.google.internal./x',         // trailing-dot bypass of the metadata name
            'http://foo.internal./confirm',                // trailing-dot bypass of the internal-suffix check
        ] as $bad) {
            $c = new Config();
            $c->promptInjectionSeeding = true;
            $c->beaconUrl = $bad;
            $c->decoySessionKey = 'unit-test-deploy-key';
            $engine = new Honeypot($this->store(), $c);
            $f = $engine->synthesize(
                $engine->classify(new RequestContext('GET', '/readme.html'), SiteProfile::empty()),
                SiteProfile::empty(),
                'seed'
            );
            self::assertNotNull($f);
            self::assertStringContainsString('already-decommissioned', $f->body, "misdirection still seeds for: {$bad}");
            $tail = substr($f->body, (int) strpos($f->body, 'already-decommissioned'));
            self::assertStringNotContainsString('http', $tail, "beacon must fail closed (no URL) for: {$bad}");
        }

        // Control: a normal public beacon URL still emits the beacon.
        $ok = new Config();
        $ok->promptInjectionSeeding = true;
        $ok->beaconUrl = 'https://beacon.example.com/confirm';
        $ok->decoySessionKey = 'unit-test-deploy-key';
        $engine = new Honeypot($this->store(), $ok);
        $f = $engine->synthesize(
            $engine->classify(new RequestContext('GET', '/readme.html'), SiteProfile::empty()),
            SiteProfile::empty(),
            'seed'
        );
        self::assertNotNull($f);
        self::assertStringContainsString('https://beacon.example.com/confirm?t=', $f->body, 'a public beacon URL still beacons');
    }

    public function test_seeded_body_within_size_cap(): void
    {
        $config = $this->seedingConfig();
        $bundle = $this->bundle('GET /readme.html');

        $canary = ['beacon' => 'https://beacon.example.test/confirm?t=' . str_repeat('a', 64)];
        $on = (new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), true, $canary))
            ->render($bundle, Style::TAUNT, 7)->body;
        $off = (new RouteTemplateEmulator($this->set(), new DirectiveRenderer(7), false, []))
            ->render($bundle, Style::TAUNT, 7)->body;

        self::assertLessThanOrEqual($config->maxBodyBytes, strlen($on), 'body must honour maxBodyBytes');
        self::assertLessThanOrEqual(2048, strlen($on) - strlen($off), 'injection block must stay under 2 KB');
    }

    public function test_no_attacker_byte_reflection(): void
    {
        // The route render passes EMPTY captures and the block is built from constants + a server-signed
        // canary — an attacker-controlled request byte can never land in the seeded block. Prove it: a
        // request whose query carries a {{canary.beacon}}-shaped marker leaves the block unchanged.
        $engine = new Honeypot($this->store(), $this->seedingConfig());
        $marker = 'EVIL{{canary.beacon}}EVIL';
        $r = new RequestContext('GET', '/readme.html', 'x=' . $marker);
        $f = $engine->synthesize($engine->classify($r, SiteProfile::empty()), SiteProfile::empty(), 'seed');
        self::assertNotNull($f);
        self::assertStringContainsString('already-decommissioned', $f->body);
        self::assertStringNotContainsString('EVIL', $f->body, 'attacker bytes must never reflect into the seeded block');
    }

    public function test_payload_constants_exist_and_are_plain(): void
    {
        // Sanity: the misdirection set is non-empty and the beacon line carries exactly the canary
        // directive (the only dynamic value).
        self::assertNotEmpty(InjectionPayloads::MISDIRECTION);
        self::assertStringContainsString('{{canary.beacon}}', InjectionPayloads::BEACON_TEMPLATE);
    }
}
