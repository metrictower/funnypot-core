<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Executes scripts/ci/check-seeded-render.php (FP-0276) so it runs under phpunit, and drives it with
 * doctored artifacts to prove each check (G1–G4 + the fail-closed floor) is NOT vacuous. Mirrors the
 * FingerprintSafetyTest script-exec pattern. All doctored artifacts are written to scratch files and
 * pointed at via the script's overrides; nothing lands in the repo.
 */
final class SeededRenderGateTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/../scripts/ci/check-seeded-render.php';

    /** @var list<string> */
    private $tmp = [];

    protected function tearDown(): void
    {
        foreach ($this->tmp as $path) {
            if (is_dir($path)) {
                foreach ((array) glob($path . '/*') as $f) {
                    @unlink($f);
                }
                @rmdir($path);
            } else {
                @unlink($path);
            }
        }
        $this->tmp = [];
    }

    private function tmpPhp(string $suffix, $data): string
    {
        $path = tempnam(sys_get_temp_dir(), 'sr-' . $suffix) . '.php';
        file_put_contents($path, "<?php\n\nreturn " . var_export($data, true) . ";\n");
        $this->tmp[] = $path;

        return $path;
    }

    private function tmpDir(): string
    {
        $dir = tempnam(sys_get_temp_dir(), 'sr-dir');
        @unlink($dir);
        @mkdir($dir);
        $this->tmp[] = $dir;

        return $dir;
    }

    /** @return array{0:int,1:string} [exitCode, output] */
    private function runGate(array $args): array
    {
        $cmd = 'php ' . escapeshellarg(self::SCRIPT);
        foreach ($args as $flag => $value) {
            $cmd .= ' ' . escapeshellarg('--' . $flag . '=' . $value);
        }
        $out = [];
        $code = 0;
        exec($cmd . ' 2>&1', $out, $code);

        return [$code, implode("\n", $out)];
    }

    private function emptyEnv(): array
    {
        return [
            'attack' => $this->tmpPhp('atk', []),
            'routes' => $this->tmpPhp('rt', []),
            'param' => $this->tmpPhp('pm', ['schema' => 1, 'buckets' => []]),
            'templates' => $this->tmpDir(),
            'surfaces' => $this->tmpPhp('sf', []),
            // Empty nuclei index so a doctored run renders the minimal-synth leg over nothing unless it
            // overrides --nuclei (the real full index is slow and would swamp a doctored case).
            'nuclei' => $this->tmpPhp('nx', ['schema' => 1, 'routes' => []]),
        ];
    }

    /**
     * emptyEnv() + one benign attack rule, so the fail-closed rule floor (:350, rule renders only)
     * passes and the doctored --nuclei synth leg is actually reached (M1(a)).
     *
     * @return array<string,string>
     */
    private function synthEnv(): array
    {
        $env = $this->emptyEnv();
        $env['attack'] = $this->tmpPhp('atk', [[
            'id' => 'attack-fp-0281-anchor',
            'response' => ['headers' => [], 'body' => 'ok'],
        ]]);

        return $env;
    }

    // --- the committed corpus ---------------------------------------------------------------------

    public function test_the_gate_passes_on_the_committed_artifacts(): void
    {
        self::assertFileExists(self::SCRIPT);
        exec('php ' . escapeshellarg(self::SCRIPT) . ' 2>&1', $out, $code);
        $text = implode("\n", $out);
        self::assertSame(0, $code, $text);
        self::assertStringContainsString('rules ×', $text);
        self::assertStringContainsString('bundles synthesized', $text, 'the minimal-synth leg must run on the committed index');
        self::assertStringContainsString('seeded surfaces verified', $text);
        // 24 rule-driven surfaces + the 2 FP-0281 synth: aggregates.
        self::assertMatchesRegularExpression('/(2[6-9]|[3-9]\d) seeded surfaces verified/', $text, 'the 24 rule surfaces + 2 synth aggregates must verify');
        self::assertMatchesRegularExpression('/[1-9]\d* fleet-constant/', $text, 'the informational inventory must be non-empty');
    }

    public function test_the_gate_is_deterministic_across_runs(): void
    {
        exec('php ' . escapeshellarg(self::SCRIPT) . ' 2>&1', $a, $ca);
        exec('php ' . escapeshellarg(self::SCRIPT) . ' 2>&1', $b, $cb);
        self::assertSame(0, $ca);
        self::assertSame(0, $cb);
        self::assertSame(implode("\n", $a), implode("\n", $b), 'the gate output must be byte-identical across runs');
    }

    // --- G4: a fleet-constant registered surface --------------------------------------------------

    public function test_g4_catches_a_registered_surface_that_is_fleet_constant(): void
    {
        $env = $this->emptyEnv();
        $env['routes'] = $this->tmpPhp('rt', [[
            'id' => 'route-fp-0276-const',
            'match' => ['template_needle' => ['fpconst']],
            'body' => 'HARD-CODED FLEET-WIDE BODY, no persona directive',
            'headers' => ['Content-Type' => 'text/plain'],
        ]]);
        $env['surfaces'] = $this->tmpPhp('sf', ['route:route-fp-0276-const' => 'must vary per deploy']);

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('route:route-fp-0276-const', $out);
        self::assertStringContainsString('identical across deploy seeds', $out);
    }

    public function test_g4_a_persona_bearing_registered_surface_passes(): void
    {
        $env = $this->emptyEnv();
        $env['routes'] = $this->tmpPhp('rt', [[
            'id' => 'route-fp-0276-varies',
            'match' => ['template_needle' => ['fpvary']],
            'body' => 'company={{persona.company.name}} domain={{persona.company.domain}}',
            'headers' => ['Content-Type' => 'text/plain'],
        ]]);
        $env['surfaces'] = $this->tmpPhp('sf', ['route:route-fp-0276-varies' => 'persona-derived']);

        [$code, $out] = $this->runGate($env);
        self::assertSame(0, $code, $out);
        self::assertStringContainsString('1 seeded surfaces verified', $out);
    }

    public function test_g4_a_surface_directive_body_varies_per_deploy(): void
    {
        // FP-0278: a route body carrying {{surface.sitemap}} renders a per-deploy-seeded <loc> set +
        // order + nouns (off the deploy seed the gate injects at each material), so G4 sees the route's
        // render path drive the new directive and vary across the two sample deploy materials.
        $env = $this->emptyEnv();
        $env['routes'] = $this->tmpPhp('rt', [[
            'id' => 'route-fp-0278-surface',
            'match' => ['template_needle' => ['fpsurface']],
            'body' => "<urlset>\n{{surface.sitemap}}\n</urlset>",
            'headers' => ['Content-Type' => 'application/xml'],
        ]]);
        $env['surfaces'] = $this->tmpPhp('sf', ['route:route-fp-0278-surface' => 'FP-0278 seeded sitemap block']);

        [$code, $out] = $this->runGate($env);
        self::assertSame(0, $code, $out);
        self::assertStringContainsString('1 seeded surfaces verified', $out);
    }

    // --- G1: a leak visible ONLY after render -----------------------------------------------------

    public function test_g1_catches_a_denylisted_token_that_appears_only_after_render(): void
    {
        // {{fake.leak4:dec:6}} renders to the bare denylisted token 922455 at the gate's render seed a
        // — the directive TEXT the static gate scans carries no such token, so only a rendered scan
        // catches it. (Value brute-forced against the gate's fixed render seeds.)
        $env = $this->emptyEnv();
        $env['attack'] = $this->tmpPhp('atk', [[
            'id' => 'attack-fp-0276-leak',
            'response' => ['headers' => [], 'body' => 'server error id {{fake.leak4:dec:6}} logged'],
        ]]);

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('G1 fingerprint leak', $out);
        self::assertStringContainsString('attack-fp-0276-leak', $out);
    }

    // --- G2: a marker absent from the base render -------------------------------------------------

    public function test_g2_catches_a_missing_marker(): void
    {
        $env = $this->emptyEnv();
        $env['attack'] = $this->tmpPhp('atk', [[
            'id' => 'attack-fp-0276-marker',
            'response' => ['headers' => [], 'body' => 'hello world'],
        ]]);
        $dir = $env['templates'];
        file_put_contents($dir . '/marker.yaml', "id: attack-fp-0276-marker\nresponse:\n  body: \"hello world\"\nexpect: ['GOODBYE_MOON']\n");

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('G2 marker missing', $out);
        self::assertStringContainsString('GOODBYE_MOON', $out);
    }

    // --- G3: nondeterminism (the built-in volatile-proof control) ---------------------------------

    public function test_g3_catches_nondeterminism_under_the_volatile_proof_arm(): void
    {
        // The committed corpus carries a {{volatile.*}} body (attack-verbose-error-volatile). With the
        // arm off (default) it renders the stable seeded token and the gate passes; with --volatile-proof
        // it mints fresh CSPRNG entropy per render, so the twin renders differ and G3 fails.
        exec('php ' . escapeshellarg(self::SCRIPT) . ' --volatile-proof 2>&1', $out, $code);
        $text = implode("\n", $out);
        self::assertSame(1, $code, $text);
        self::assertStringContainsString('G3 nondeterministic render', $text);
    }

    // --- the FP-0281 minimal-synth (--nuclei) leg -------------------------------------------------

    public function test_synth_leg_body_order_and_names_vary_across_deploys(): void
    {
        // A 6-word bundle (order collision ~1/720 across the two sample seeds) + one hw witness, with
        // both aggregate surfaces registered ⇒ both verify.
        $env = $this->synthEnv();
        $env['nuclei'] = $this->tmpPhp('nx', ['schema' => 1, 'routes' => ['GET /fp-0281' => ['b' => [[
            's' => 200,
            'bw' => ['alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot'],
            'hw' => ['WIDGET'],
            'nf' => [], 'sz' => null, 'rx' => [], 'h' => [], 't' => ['fp-0281'], 'pid' => '', 'sev' => 'info', 'sig' => 1,
        ]]]]]);
        $env['surfaces'] = $this->tmpPhp('sf', [
            'synth:minimal-body-order' => 'FP-0281 deploy-seeded bw word order',
            'synth:witness-header-names' => 'FP-0281 deploy-seeded witness-header names',
        ]);

        [$code, $out] = $this->runGate($env);
        self::assertSame(0, $code, $out);
        self::assertStringContainsString('2 seeded surfaces verified', $out);
        self::assertStringContainsString('1 bundles synthesized', $out);
    }

    public function test_synth_leg_body_order_surface_fails_closed_with_no_multi_word_bundle(): void
    {
        // Single-word-only bundles never permute, so there is nothing for the body-order surface to
        // measure — it must NOT be recorded (M1(b)): a registered key then fails as a stale-registry
        // entry rather than silently passing or dividing by zero.
        $env = $this->synthEnv();
        $env['nuclei'] = $this->tmpPhp('nx', ['schema' => 1, 'routes' => ['GET /fp-0281-one' => ['b' => [[
            's' => 200, 'bw' => ['lonelyword'], 'nf' => [], 'sz' => null, 'rx' => [], 'h' => [], 't' => ['x'], 'pid' => '', 'sev' => 'info', 'sig' => 1,
        ]]]]]);
        $env['surfaces'] = $this->tmpPhp('sf', ['synth:minimal-body-order' => 'must vary per deploy']);

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('synth:minimal-body-order', $out);
        self::assertStringContainsString('names no rendered rule', $out);
    }

    public function test_synth_leg_g1_catches_a_denylisted_bw_word(): void
    {
        // A denylisted token in a served bw word is only visible after minimal synthesis — the leg's G1
        // scan must catch it.
        $env = $this->synthEnv();
        $env['nuclei'] = $this->tmpPhp('nx', ['schema' => 1, 'routes' => ['GET /fp-0281-leak' => ['b' => [[
            's' => 200, 'bw' => ['mod_security'], 'nf' => [], 'sz' => null, 'rx' => [], 'h' => [], 't' => ['x'], 'pid' => '', 'sev' => 'info', 'sig' => 1,
        ]]]]]);

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('G1 fingerprint leak in synth', $out);
    }

    public function test_synth_leg_stale_registry_key_fails_closed_on_empty_index(): void
    {
        // A registered synth: key with an empty nuclei index records no surface ⇒ the stale-registry
        // guard fires (M1(b): the floor is never computed on an empty leg — no div-by-zero).
        $env = $this->synthEnv();
        $env['surfaces'] = $this->tmpPhp('sf', ['synth:minimal-body-order' => 'registered but nothing rendered']);

        [$code, $out] = $this->runGate($env);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('names no rendered rule', $out);
    }

    // --- fail-closed floor ------------------------------------------------------------------------

    public function test_zero_rules_rendered_fails_closed(): void
    {
        [$code, $out] = $this->runGate($this->emptyEnv());
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('no rules rendered', $out);
    }
}
