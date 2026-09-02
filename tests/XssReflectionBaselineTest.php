<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0259 Part A — the owned XSS reflection BASELINE (id `attack-xss-baseline`).
 *
 * The rule owns ONE synthetic search path (`/products/quick-search`) and echoes ONE query value
 * that is WHOLLY [A-Za-z0-9]{1,64}. That character class IS the whitelist: the reflected string is
 * ALWAYS the named capture `marker`, so it can NEVER carry a markup-forming byte. dalfox's benign
 * 36-char discovery marker round-trips (so its Stage-0/1/2 discovery engages), while any
 * out-of-charset byte makes the anchored, delimiter-bounded capture FAIL — the baseline declines
 * and a canned decoy (attack-crs-xss / attack-ssti-numeric) serves instead. Full-tag reflection
 * stays on the UNCHANGED attack-xss under the FP-0236 gate (reflect_class:xss + isolatedOrigin).
 *
 * The baseline is inert BY CHARSET (not by the isolated-origin gate): it is NOT a reflects_input
 * rule (it asserts `html_safe_captures: true`, compile-time only), so the marker reflects on a
 * DEFAULT (embedded, isolatedOrigin=false) install — that is the whole deliverable.
 */
final class XssReflectionBaselineTest extends TestCase
{
    private const PATH = '/products/quick-search';
    private const BASELINE_ID = 'attack-xss-baseline';

    // dalfox's bracketed discovery marker shape: `dlx`+8hex . `dlxmid`+8hex . `xld`+8hex = 36 chars,
    // wholly alphanumeric. (Attacker-supplied input, reflected at runtime — NOT a served static byte;
    // the shipped template body carries no scanner token, per the fingerprint-safety gate.)
    private const MARKER36 = 'dlx0a1b2c3ddlxmid4e5f6a7bxld8c9d0e1f';
    private const MARKER64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab';

    // dalfox SPECIAL_PROBE_CHARS (src/parameter_analysis/mod.rs): every byte the scanner probes to
    // decide whether raw-angle payloads are worth sending. None is in [A-Za-z0-9].
    private const SPECIAL_PROBE_CHARS = ['/', '\\', '\'', '{', '`', '<', '>', '"', '(', ')', ';', '=', '|', '}', '[', '.', ':', ']', '+', ',', '$', '-'];

    private const PROBE_OPEN = 'dlx0a1b2c3d';
    private const PROBE_CLOSE = 'xld8c9d0e1f';

    private function honeypot(bool $isolatedOrigin): Honeypot
    {
        return Honeypot::default($this->config($isolatedOrigin, [], []));
    }

    /**
     * @param array<string,bool> $reflectClasses
     * @param string[]           $exclude
     */
    private function config(bool $isolatedOrigin, array $reflectClasses, array $exclude): Config
    {
        $config = new Config(
            'respond',                                                  // mode
            static function (RequestContext $r): bool { return true; }, // gate
            'matched-only',                                             // pathScope
            null,                                                       // personaSeed
            'coherent',                                                 // personaBreadth
            Style::MINIMAL,                                             // responseStyle
            'high',                                                     // severityCeiling
            65536,                                                      // maxBodyBytes
            0,                                                          // latencyMs
            0,                                                          // latencyJitterMs
            true                                                        // attackEmulation
        );
        $config->isolatedOrigin = $isolatedOrigin;
        $config->reflectClasses = $reflectClasses;
        $config->exclude = $exclude;

        return $config;
    }

    private static function req(string $query): RequestContext
    {
        return new RequestContext('GET', self::PATH, $query);
    }

    private function templateIds(Honeypot $hp, RequestContext $r): array
    {
        return $hp->classify($r, SiteProfile::empty())->detection->templateIds();
    }

    // --- Part A: the benign marker reflects inline, on a DEFAULT install (AC 1) ---

    public function test_dalfox_bracketed_marker_round_trips_inline(): void
    {
        // isolatedOrigin=false is the fail-safe default; the baseline is independent of the gate.
        $hp = $this->honeypot(false);
        $resp = $hp->respond(self::req('q=' . self::MARKER36));

        self::assertNotNull($resp, 'the alnum marker must reflect on a default install');
        self::assertSame(200, $resp->status);
        self::assertStringStartsWith('text/html', (string) $resp->headers['Content-Type']);
        self::assertStringContainsString(self::MARKER36, $resp->body);
        self::assertSame(self::BASELINE_ID, $resp->servedBy->ruleId);

        // Byte-identical under an isolated origin: the baseline never consults the reflect gate.
        $iso = $this->honeypot(true)->respond(self::req('q=' . self::MARKER36));
        self::assertNotNull($iso);
        self::assertSame($resp->body, $iso->body);
    }

    public function test_benign_keyword_reflects_inline(): void
    {
        $resp = $this->honeypot(false)->respond(self::req('q=laptop'));
        self::assertNotNull($resp);
        self::assertStringContainsString('laptop', $resp->body);
        self::assertSame(self::BASELINE_ID, $resp->servedBy->ruleId);
    }

    public function test_marker_length_cap_admits_36_and_64_refuses_65(): void
    {
        $hp = $this->honeypot(false);

        // 36 and 64 alnum chars reflect.
        self::assertSame(36, strlen(self::MARKER36));
        self::assertSame(64, strlen(self::MARKER64));
        $r36 = $hp->respond(self::req('q=' . self::MARKER36));
        self::assertNotNull($r36);
        self::assertStringContainsString(self::MARKER36, $r36->body);
        $r64 = $hp->respond(self::req('q=' . self::MARKER64));
        self::assertNotNull($r64);
        self::assertStringContainsString(self::MARKER64, $r64->body);

        // 65 alnum chars: the length cap makes the capture FAIL — the baseline declines and never
        // reflects the over-long value (nothing else matches a pure-alnum value ⇒ null).
        $over = self::MARKER64 . 'e'; // 65 chars, still wholly alnum
        self::assertNotContains(self::BASELINE_ID, $this->templateIds($hp, self::req('q=' . $over)));
        $rOver = $hp->respond(self::req('q=' . $over));
        if ($rOver !== null) {
            self::assertNotSame(self::BASELINE_ID, $rOver->servedBy->ruleId);
            self::assertStringNotContainsString($over, $rOver->body);
        } else {
            self::assertNull($rOver);
        }
    }

    // --- THE ANTI-SINK PROOF (R1): out-of-charset bytes are NEVER reflected by the baseline ---

    /**
     * @dataProvider outOfCharsetProvider
     */
    public function test_out_of_charset_bytes_are_never_reflected(string $query, string $mustNotAppear): void
    {
        // isolatedOrigin=false — the default install AND the mode where attack-xss is gate-suppressed,
        // so the ONLY thing that could reflect an out-of-charset byte here is the baseline. It never
        // does: the capture class refuses, so the baseline declines and a canned decoy serves.
        $hp = $this->honeypot(false);
        $r = self::req($query);

        // (1) The baseline never claims the request.
        self::assertNotContains(
            self::BASELINE_ID,
            $this->templateIds($hp, $r),
            "baseline must decline out-of-charset q: {$query}"
        );

        // (2) Whatever serves (a canned decoy, or nothing) is not the baseline, and does not echo the
        //     out-of-charset payload.
        $resp = $hp->respond($r);
        if ($resp !== null) {
            self::assertNotSame(self::BASELINE_ID, $resp->servedBy->ruleId, "served by baseline for: {$query}");
            self::assertStringNotContainsString($mustNotAppear, $resp->body, "reflected out-of-charset bytes for: {$query}");
        } else {
            self::assertNull($resp);
        }
    }

    /**
     * @return iterable<string,array{0:string,1:string}>
     */
    public static function outOfCharsetProvider(): iterable
    {
        // Every dalfox SPECIAL_PROBE_CHARS byte, sandwiched in the marker (open+char+close), raw and
        // percent-encoded — the exact probes dalfox uses to test whether specials survive.
        foreach (self::SPECIAL_PROBE_CHARS as $c) {
            $probe = self::PROBE_OPEN . $c . self::PROBE_CLOSE;
            yield 'special-raw ' . bin2hex($c) => ['q=' . $probe, self::PROBE_OPEN];
            yield 'special-enc ' . bin2hex($c) => ['q=' . self::PROBE_OPEN . rawurlencode($c) . self::PROBE_CLOSE, self::PROBE_OPEN];
        }

        // Assorted markup / injection shapes.
        yield 'full script tag'        => ['q=<script>alert(1)</script>', '<script>'];
        yield 'encoded angle brackets' => ['q=%3Cscript%3E', '%3Cscript%3E'];
        yield 'attribute breakout'     => ['q="onmouseover=x', '"onmouseover=x'];
        yield 'space'                  => ['q=a b', 'a b'];
        yield 'ssti fence'             => ['q=a{{7*7}}', '{{7*7}}'];
        yield 'nul byte'               => ['q=a%00b', "a\x00b"];
        yield 'crlf'                   => ['q=a%0d%0ab', "a\r\nb"];
        yield 'multibyte'              => ['q=' . rawurlencode('ünïcode'), 'ünïcode'];
        yield 'empty value'            => ['q=', self::PATH];
    }

    /**
     * Capture-class-bound (not "whole rule declines"): a query that carries markup BEFORE a clean
     * alnum `q` reflects ONLY the alnum capture — never the markup. Proves the reflected region is
     * bounded to [A-Za-z0-9] even when the rule DOES match.
     */
    public function test_reflection_is_bounded_to_the_alnum_capture(): void
    {
        $resp = $this->honeypot(false)->respond(self::req('q=abc<script>&q=def123'));
        self::assertNotNull($resp);
        self::assertSame(self::BASELINE_ID, $resp->servedBy->ruleId);
        self::assertStringContainsString('def123', $resp->body);
        self::assertStringNotContainsString('<script>', $resp->body);
        self::assertStringNotContainsString('abc<', $resp->body);
    }

    // --- Full-tag escalation stays gated on attack-xss, off by default (AC 3) ---

    public function test_full_tag_escalation_stays_on_attack_xss_gated_off_by_default(): void
    {
        $payload = '<script>alert(document.domain)</script>';
        $r = self::req('q=' . $payload);

        // The baseline refuses; attack-xss (unchanged) is the rule that claims a full tag.
        $ids = $this->templateIds($this->honeypot(false), $r);
        self::assertContains('attack-xss', $ids);
        self::assertNotContains(self::BASELINE_ID, $ids);

        // Default (embedded) install: reflection withheld.
        self::assertNull($this->honeypot(false)->respond($r));

        // Isolated origin but xss class disabled: still withheld.
        $off = Honeypot::default($this->config(true, ['xss' => false], []));
        self::assertNull($off->respond($r));

        // Isolated origin, gate open: attack-xss (NOT the baseline) reflects the full tag.
        $on = $this->honeypot(true)->respond($r);
        self::assertNotNull($on);
        self::assertStringContainsString($payload, $on->body);
        self::assertSame('attack-xss', $on->servedBy->ruleId);
    }

    // --- Not a reflect-everything host (AC 2) ---

    public function test_does_not_present_as_reflect_everything(): void
    {
        $hp = $this->honeypot(false);

        // (i) The marker on some OTHER path is not echoed by the baseline.
        $off = $hp->respond(new RequestContext('GET', '/nope', 'q=' . self::MARKER36));
        if ($off !== null) {
            self::assertStringNotContainsString(self::MARKER36, $off->body);
        }

        // (ii) A different param name on the owned path does not reflect (only `q`).
        self::assertNotContains(self::BASELINE_ID, $this->templateIds($hp, self::req('search=' . self::MARKER36)));
        $bySearch = $hp->respond(self::req('search=' . self::MARKER36));
        if ($bySearch !== null) {
            self::assertStringNotContainsString(self::MARKER36, $bySearch->body);
        }

        // (iii) dalfox's sentinel-name pre-probe (a sentinel PARAM NAME) does not reflect: only the
        //       real `q` value is echoed, so the host does not look like a reflect-everything origin.
        $sentinel = $hp->respond(self::req('q=laptop&dlfx_sentinel_q_8a3f=' . self::MARKER36));
        self::assertNotNull($sentinel);
        self::assertStringContainsString('laptop', $sentinel->body);
        self::assertStringNotContainsString(self::MARKER36, $sentinel->body);

        // (iv) No query at all ⇒ the baseline declines (needs a `q` value).
        self::assertNotContains(self::BASELINE_ID, $this->templateIds($hp, self::req('')));
    }

    // --- Determinism (same request ⇒ same served bytes) ---

    public function test_served_bytes_are_deterministic(): void
    {
        $hp = $this->honeypot(false);
        $a = $hp->respond(self::req('q=' . self::MARKER36));
        $b = $hp->respond(self::req('q=' . self::MARKER36));
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body);

        // A different marker changes only the reflected token (persona seed is host-derived, stable).
        $c = $hp->respond(self::req('q=' . self::MARKER64));
        self::assertNotNull($c);
        self::assertSame(
            str_replace(self::MARKER36, self::MARKER64, $a->body),
            $c->body
        );
    }

    // --- Operator opt-out is ID-only for the attack tier (N1) ---

    public function test_operator_can_opt_out_via_exclude_id(): void
    {
        // The attack-tier opt-out is the rule's ID (TemplateAttackEmulator::disable is id-only).
        $byId = Honeypot::default($this->config(false, [], [self::BASELINE_ID]));
        self::assertNotContains(self::BASELINE_ID, $this->templateIds($byId, self::req('q=' . self::MARKER36)));
        self::assertNull($byId->respond(self::req('q=' . self::MARKER36)));

        // A TAG is NOT an attack-tier opt-out (tag exclusion works only for route bundles), so the
        // baseline still fires when excluded by tag — documents the N1 correction.
        $byTag = Honeypot::default($this->config(false, [], ['xss']));
        $resp = $byTag->respond(self::req('q=' . self::MARKER36));
        self::assertNotNull($resp, 'tag exclusion does not disable an attack-tier rule');
        self::assertSame(self::BASELINE_ID, $resp->servedBy->ruleId);
    }

    // --- A benign visitor classifies ATTACK_CLASS at low severity (documented R4) ---

    public function test_benign_visitor_classifies_low_severity(): void
    {
        $verdict = $this->honeypot(false)->classify(self::req('q=laptop'), SiteProfile::empty());
        self::assertSame(Verdict::ATTACK_CLASS, $verdict->classification);
        self::assertContains(self::BASELINE_ID, $verdict->detection->templateIds());
        self::assertSame('low', $verdict->detection->highestSeverity);
    }

    // --- The compiled shape is pinned (guards the load-bearing whitelist against a widening) ---

    public function test_compiled_shape_is_pinned(): void
    {
        $attack = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $rule = $attack->ruleById(self::BASELINE_ID);

        self::assertNotNull($rule);
        self::assertSame(200, $rule['status']);
        // NOT a reflects_input rule and NO reflect_class: inert by charset, serves inline.
        self::assertTrue(empty($rule['reflects_input']));
        self::assertArrayNotHasKey('reflect_class', $rule);
        // Scoped to one path via a literal prefilter.
        self::assertSame('/products/quick-search', $rule['lit']);
        self::assertSame('path', $rule['lit_in']);
        // The query condition carries capture:true and the EXACT whitelist regex.
        self::assertSame('path', $rule['match'][0]['in']);
        self::assertSame('query', $rule['match'][1]['in']);
        self::assertTrue($rule['match'][1]['capture']);
        self::assertSame('(?:^|&)q=(?P<marker>[A-Za-z0-9]{1,64})(?:&|$)', $rule['match'][1]['regex']);
    }

    public function test_yaml_recompiles_to_the_committed_artifact_entry(): void
    {
        $dir = sys_get_temp_dir() . '/funnypot-xssbaseline-' . getmypid() . '-' . uniqid();
        self::assertTrue(mkdir($dir, 0775, true) || is_dir($dir));
        copy(__DIR__ . '/../templates/attack/64-xss-reflection-baseline.yaml', $dir . '/rule.yaml');
        try {
            $compiled = (new EmulatorCompiler())->compile($dir);
        } finally {
            @unlink($dir . '/rule.yaml');
            @rmdir($dir);
        }

        $fresh = null;
        foreach ($compiled as $rule) {
            if (($rule['id'] ?? '') === self::BASELINE_ID) {
                $fresh = $rule;
            }
        }
        self::assertNotNull($fresh, 'the single-YAML compile must yield the baseline rule');

        $committed = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php')
            ->ruleById(self::BASELINE_ID);
        self::assertSame($committed, $fresh, 'committed artifact entry must match a fresh recompile (zero hand-edit drift)');
    }
}
