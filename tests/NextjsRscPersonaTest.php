<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0229 — Next.js App-Router / RSC persona (CVE-2025-55182/-55183/-55184, "React2Shell").
 *
 * Drives the REAL engine over the FULL compiled index (nuclei-index.full.php) + compiled attack file,
 * the AiOwnsPathTest pattern — so classify()'s owns_path override + the persona gate run on the true
 * serve path, not a stub. Acceptance harness for:
 *   (a) framework fingerprint on a Next.js-selected seed (shell markers)
 *   (b) RSC wire, gated ON (text/x-component + body `0:`)
 *   (c) [B3] gate OFF for a served-non-Next.js seed AND gate ON for a served-Next.js seed, under a
 *       NON-DEFAULT config where the candidate set differs from the raw set (exclude / nucleiReflection
 *       off) — the fleet-coherence assertion that can only pass if the gate reproduces the serve pick
 *   (d) inert / no reflection of the `_rsc` value
 *   (e) affected-side pinned version
 *   (f) [B1][B2] compiled-artifact falsifier (route-nextjs at GET / w=8; persona_gate on the rule)
 * plus the FingerprintGuard sanity scan and the homepage-not-404 regression guard for owning `/`.
 */
final class NextjsRscPersonaTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    /** The affected-side pool the persona renders, each strictly below its line's patched release. */
    private const AFFECTED = ['15.5.4', '15.4.6', '15.3.4', '15.2.3', '16.0.5'];
    private const PATCHED = ['15.5' => '15.5.7', '15.4' => '15.4.8', '15.3' => '15.3.6', '15.2' => '15.2.6', '16.0' => '16.0.7'];

    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private function index(): array
    {
        if (self::$index === null) {
            self::$index = require self::INDEX;
        }

        return self::$index;
    }

    /**
     * A full engine pinned to one persona seed, attack tier live, root `/` allowed to serve (a
     * probe-signature closure that returns true). $exclude / $nucleiReflection let a test drive a
     * NON-DEFAULT config where candidates() differs from the raw bundle set (the C2c divergence case).
     *
     * @param string[] $exclude
     */
    private function engine(string $seed, array $exclude = [], bool $nucleiReflection = true): Honeypot
    {
        return new Honeypot(new PhpArrayStore($this->index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },   // gate open
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; }, // seedFor = seed.'|'
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            true,   // attackEmulation ⇒ classify() runs the owns_path override + persona gate
            null,
            null,
            static function (RequestContext $r): bool { return true; },   // probeSignature ⇒ root '/' serves
            '',
            $exclude,
            $nucleiReflection
        ));
    }

    /** The deploy's served `/` persona is route-nextjs ⟺ its shell body carries the App-Router marker. */
    private function servedNextjs(Honeypot $e): bool
    {
        $r = $e->respond(new RequestContext('GET', '/'));

        return $r !== null && strpos($r->body, 'self.__next_f') !== false;
    }

    private function rscReq(string $query = '_rsc=1'): RequestContext
    {
        return new RequestContext('GET', '/', $query, ['RSC' => '1'], '');
    }

    /**
     * First seed (0..$max) whose SERVED `/` persona is route-nextjs, under the given config — proving
     * the shell was folded into the served set (spec [B1]) and rides the lottery. Fails the test if
     * none is found in range (the shell would be unreachable).
     *
     * @param string[] $exclude
     */
    private function firstNextjsSeed(int $max = 5000, array $exclude = [], bool $nucleiReflection = true): string
    {
        for ($s = 0; $s <= $max; $s++) {
            if ($this->servedNextjs($this->engine((string) $s, $exclude, $nucleiReflection))) {
                return (string) $s;
            }
        }
        self::fail("no route-nextjs-selecting seed found in 0..{$max} — the shell is not in the served GET / set");
    }

    /**
     * @param string[] $exclude
     */
    private function firstNonNextjsSeed(int $max = 5000, array $exclude = [], bool $nucleiReflection = true): string
    {
        for ($s = 0; $s <= $max; $s++) {
            if (!$this->servedNextjs($this->engine((string) $s, $exclude, $nucleiReflection))) {
                return (string) $s;
            }
        }
        self::fail("every seed served route-nextjs in 0..{$max} — cannot exercise the gate-closed branch");
    }

    // --- (a) framework fingerprint on a Next.js-selected seed ---------------------------------------

    public function test_a_shell_markers_on_a_nextjs_selected_seed(): void
    {
        $seed = $this->firstNextjsSeed();
        $resp = $this->engine($seed)->respond(new RequestContext('GET', '/'));

        self::assertNotNull($resp, 'the shell must serve for a route-nextjs seed');
        self::assertSame(200, $resp->status);
        self::assertStringContainsString('self.__next_f', $resp->body, 'App-Router bootstrap marker');
        self::assertStringContainsString('__next_f', $resp->body, 'the OR-marker variant');
        self::assertStringContainsString('_next/static', $resp->body, 'asset-ref marker');
        self::assertStringNotContainsString('__NEXT_DATA__', $resp->body, 'App Router omits the Pages-Router marker');
        self::assertSame('Next.js', $resp->headers['X-Powered-By'] ?? null, 'per-bundle X-Powered-By header');
    }

    // --- (b) RSC wire, gated ON --------------------------------------------------------------------

    public function test_b_rsc_flight_served_when_gate_open(): void
    {
        $seed = $this->firstNextjsSeed();
        $resp = $this->engine($seed)->respond($this->rscReq());

        self::assertNotNull($resp, 'RSC probe must serve on a nextjs deploy (gate open)');
        self::assertSame(200, $resp->status);
        self::assertSame('text/x-component', $resp->headers['Content-Type'] ?? null);
        self::assertSame('0:', substr($resp->body, 0, 2), 'React Flight root row is line 0');
    }

    // --- (c) [B3] gate coherence under a NON-DEFAULT config (the divergence assertion) --------------

    public function test_c_gate_coheres_with_serve_under_exclude_config(): void
    {
        // Remove several non-nextjs personas from GET / so candidates() != the raw bundle set. A gate
        // that picked over the RAW set would remap crc32(seed)%sum and diverge from what is served; a
        // gate that reproduces the serve pick cannot. Both branches must be present and coherent.
        $b = $this->index()['routes']['GET /']['b'];
        $exclude = [];
        foreach ($b as $bundle) {
            $pid = (string) ($bundle['pid'] ?? '');
            if ($pid !== '' && $pid !== 'route-nextjs' && count($exclude) < 5) {
                $exclude[] = $pid;
            }
        }
        self::assertNotEmpty($exclude, 'need excludable non-nextjs pids at GET /');

        $nextSeed = $this->firstNextjsSeed(5000, $exclude);
        $otherSeed = $this->firstNonNextjsSeed(5000, $exclude);

        // Dual: served-nextjs seed ⇒ gate OPEN (no false-close under raw!=filtered).
        $open = $this->engine($nextSeed, $exclude)->respond($this->rscReq());
        self::assertNotNull($open, 'gate must be OPEN for a served-nextjs seed under exclude');
        self::assertSame('text/x-component', $open->headers['Content-Type'] ?? null);

        // Primary: served-non-nextjs seed ⇒ gate CLOSED (no text/x-component fleet leak).
        $closed = $this->engine($otherSeed, $exclude)->respond($this->rscReq());
        if ($closed !== null) {
            self::assertNotSame(
                'text/x-component',
                $closed->headers['Content-Type'] ?? null,
                'gate must be CLOSED for a served-non-nextjs seed (no RSC leak)'
            );
        }

        // Full sweep: gate-open ⟺ served-nextjs for every seed in a bounded range, under this config.
        for ($s = 0; $s <= 400; $s++) {
            $e = $this->engine((string) $s, $exclude);
            $servedNext = $this->servedNextjs($e);
            $flight = $this->engine((string) $s, $exclude)->respond($this->rscReq());
            $gateOpen = $flight !== null && ($flight->headers['Content-Type'] ?? null) === 'text/x-component';
            self::assertSame($servedNext, $gateOpen, "seed {$s}: gate-open must equal served-nextjs (exclude cfg)");
        }
    }

    public function test_c_gate_coheres_under_nuclei_reflection_off(): void
    {
        // nucleiReflection:false drops every non-route-* bundle, so the ONLY GET / candidate is
        // route-nextjs ⇒ served `/` is nextjs for every seed. A raw-set gate would still pick over all
        // 41 bundles and mostly say "not nextjs" (the false-CLOSE dual leak). Our gate uses the same
        // filtered candidates ⇒ OPEN for every seed. raw != filtered here too.
        for ($s = 0; $s <= 60; $s++) {
            $e = $this->engine((string) $s, [], false);
            self::assertTrue($this->servedNextjs($e), "seed {$s}: only route-* survives, served must be nextjs");
            $flight = $this->engine((string) $s, [], false)->respond($this->rscReq());
            self::assertNotNull($flight, "seed {$s}: gate must be OPEN (no false-close)");
            self::assertSame('text/x-component', $flight->headers['Content-Type'] ?? null);
        }
    }

    public function test_c_plain_get_root_declines_to_the_lottery_not_the_rsc(): void
    {
        // A plain GET / (no _rsc) must NOT match the RSC rule — it falls through to the persona lottery
        // (shell or another persona), never text/x-component.
        $nextSeed = $this->firstNextjsSeed();
        $shell = $this->engine($nextSeed)->respond(new RequestContext('GET', '/'));
        self::assertNotNull($shell);
        self::assertNotSame('text/x-component', $shell->headers['Content-Type'] ?? null);
    }

    // --- Regression: owning `/` must not 404 the homepage on a non-nextjs deploy -------------------

    public function test_owning_root_does_not_404_homepage_on_non_nextjs_deploy(): void
    {
        // GET / carries a session-cookie persona (sails.sid). The old auth-success-witness guard would
        // suppress the homepage on a decline once `/` is owned; the root-entry exemption keeps the
        // lottery serving. Both a plain GET / and an RSC probe on a non-nextjs seed must still serve a
        // homepage (never a 404 / CLEAN suppression) — and never the nextjs shell.
        $otherSeed = $this->firstNonNextjsSeed();
        $plain = $this->engine($otherSeed)->respond(new RequestContext('GET', '/'));
        self::assertNotNull($plain, 'plain GET / must still serve a persona homepage, not 404');
        self::assertStringNotContainsString('self.__next_f', $plain->body, 'a non-nextjs deploy shows no Next.js markers at /');
    }

    // --- (d) inert / no reflection -----------------------------------------------------------------

    public function test_d_rsc_body_does_not_reflect_input(): void
    {
        $seed = $this->firstNextjsSeed();
        $canary = 'CANARY7a3f2b1c';
        $resp = $this->engine($seed)->respond(new RequestContext('GET', '/', '_rsc=' . $canary, ['RSC' => '1'], ''));

        self::assertNotNull($resp);
        self::assertStringNotContainsString($canary, $resp->body, 'the _rsc value must never be reflected into the flight body');
        foreach ($resp->headers as $v) {
            self::assertStringNotContainsString($canary, (string) $v, 'no reflection into a header either');
        }
    }

    // --- (e) affected-side pinned version ----------------------------------------------------------

    public function test_e_version_is_affected_side_for_every_deploy(): void
    {
        for ($s = 0; $s <= 400; $s++) {
            $v = PersonaIdentity::fromSeed($s)->field('nextjs.version');
            self::assertContains($v, self::AFFECTED, "seed {$s}: nextjs.version must be from the affected pool");
            $line = implode('.', array_slice(explode('.', (string) $v), 0, 2));
            self::assertArrayHasKey($line, self::PATCHED);
            self::assertTrue(
                version_compare((string) $v, self::PATCHED[$line], '<'),
                "seed {$s}: {$v} must be strictly below its patched release {$this->patched($line)}"
            );
        }

        // And the SERVED shell carries an affected-side version (rendered from the deploy identity;
        // the flight payload escapes its quotes, so match the version token directly).
        $seed = $this->firstNextjsSeed();
        $body = $this->engine($seed)->respond(new RequestContext('GET', '/'))->body;
        $foundAffected = false;
        foreach (self::AFFECTED as $v) {
            if (strpos($body, $v) !== false) {
                $foundAffected = true;
            }
        }
        self::assertTrue($foundAffected, 'served shell must render an affected-side nextjs version');
        foreach (self::PATCHED as $patched) {
            self::assertStringNotContainsString($patched, $body, 'served shell must never render a patched version');
        }
    }

    private function patched(string $line): string
    {
        return self::PATCHED[$line];
    }

    // --- (f) [B1][B2] compiled-artifact falsifier --------------------------------------------------

    public function test_f_compiled_index_and_rule_are_wired(): void
    {
        $b = $this->index()['routes']['GET /']['b'] ?? [];
        $nextjs = array_values(array_filter($b, static function (array $bundle): bool {
            return ($bundle['pid'] ?? null) === 'route-nextjs';
        }));
        self::assertCount(1, $nextjs, 'exactly one route-nextjs bundle folded into GET /');
        self::assertSame(8, (int) ($nextjs[0]['w'] ?? 0), 'the capped-key fold forces w=8 (spec [B1])');
        self::assertSame(1, (int) ($nextjs[0]['sig'] ?? 0), 'the shell is sig=1 so GET / stays a root entry');

        $rules = require self::ATTACK;
        $rule = null;
        foreach ($rules as $r) {
            if (($r['id'] ?? '') === 'attack-nextjs-rsc') {
                $rule = $r;
                break;
            }
        }
        self::assertNotNull($rule, 'the RSC rule must compile');
        self::assertSame('route-nextjs', $rule['persona_gate'] ?? null, 'persona_gate threaded == the compiled pid');
        self::assertContains('/', $rule['owns_path'] ?? [], 'the rule owns /');
    }

    // --- FingerprintGuard sanity (compile gate is the CI authority; this is belt-and-suspenders) ----

    public function test_rendered_bodies_are_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $seed = $this->firstNextjsSeed();

        $shell = $this->engine($seed)->respond(new RequestContext('GET', '/'));
        self::assertSame([], $guard->scan($shell->body), 'shell body must be fingerprint-clean');
        foreach ($shell->headers as $v) {
            self::assertSame([], $guard->scan((string) $v), 'shell header must be fingerprint-clean');
        }

        $flight = $this->engine($seed)->respond(new RequestContext('GET', '/', '_rsc=1', ['RSC' => '1'], ''));
        self::assertSame([], $guard->scan($flight->body), 'flight body must be fingerprint-clean');
    }
}
