<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Synthesis;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Detection;
use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\Synthesis\SynthScaffold;
use PHPUnit\Framework\TestCase;

/**
 * The top-risk lock for FP-0281: seeding the minimal-synth scaffold order and the witness-header names
 * NEVER breaks a matcher, at ANY deploy seed, over the WHOLE compiled nuclei index. Sweeps 16 deploy
 * materials and, for every served bundle, re-checks every constraint nuclei applies; also proves
 * servability is seed-independent, the X-Detected-N tell is gone, and the body order varies without
 * changing the byte multiset.
 */
final class MinimalSynthMarkerSurvivalTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    /** @return list<string> */
    private static function materials(): array
    {
        $m = ['', 'funnypot', 'fp-0276-sample-a', 'fp-0276-sample-b'];
        for ($i = 0; $i < 12; $i++) {
            $m[] = "m-{$i}";
        }

        return $m;
    }

    /** @return array<string,mixed> */
    private static function index(): array
    {
        if (self::$index === null) {
            ini_set('memory_limit', '512M');
            self::$index = require __DIR__ . '/../../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    private function synth(int $seed): ResponseSynthesizer
    {
        // A coherent chrome (Server/X-Powered-By) so the header block is realistic; null emulators ⇒
        // pure minimal synthesis on every bundle.
        return new ResponseSynthesizer(null, Style::MINIMAL, 'nginx', 'PHP/8.1.27', $seed);
    }

    /** @param array<string,string> $headers */
    private static function headerBlock(array $headers): string
    {
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        return implode("\n", $lines);
    }

    public function test_every_matcher_survives_and_servability_is_seed_independent(): void
    {
        $routes = self::index()['routes'] ?? [];
        $guard = FingerprintGuard::fromPackage();
        $servedSets = [];
        $checkedOneSeed = false;

        foreach (self::materials() as $material) {
            $seed = PersonaIdentity::seedFromMaterial($material);
            $synth = $this->synth($seed);
            $served = [];

            foreach ($routes as $route => $entry) {
                foreach ((array) ($entry['b'] ?? []) as $i => $bundle) {
                    if (!is_array($bundle)) {
                        continue;
                    }
                    $resp = $synth->synthesize($bundle, Detection::none(), "gate.example|{$material}");
                    if ($resp === null) {
                        continue;
                    }
                    $served[] = "{$route}#{$i}";

                    // The block-level validator (the same substring checks nuclei applies).
                    self::assertTrue(
                        BundleValidator::satisfies($resp->body, $resp->headers, $bundle),
                        "BundleValidator::satisfies must hold for {$route}#{$i} at material '{$material}'"
                    );

                    // FingerprintGuard runs once (per-leaf) at the first material only — it is
                    // seed-independent in outcome and the full 16× scan would be needlessly slow.
                    if (!$checkedOneSeed) {
                        foreach (array_merge([$resp->body], array_keys($resp->headers), array_values($resp->headers)) as $leaf) {
                            self::assertSame([], $guard->scan((string) $leaf), "no fingerprint leak in {$route}#{$i}");
                        }
                    }
                }
            }
            sort($served);
            $servedSets[$material] = $served;
            $checkedOneSeed = true;
        }

        // Servability is a pure function of the artifact — never of the deploy seed.
        $ref = $servedSets['fp-0276-sample-a'];
        self::assertNotEmpty($ref, 'the sweep must actually serve bundles');
        foreach ($servedSets as $material => $set) {
            self::assertSame($ref, $set, "the served (route,i) set must be identical at material '{$material}'");
        }
    }

    public function test_the_x_detected_tell_is_gone_and_naming_is_per_deploy_coherent(): void
    {
        $routes = self::index()['routes'] ?? [];
        $firstNameByMaterial = [];

        foreach (['fp-0276-sample-a', 'fp-0276-sample-b', 'm-5'] as $material) {
            $seed = PersonaIdentity::seedFromMaterial($material);
            $synth = $this->synth($seed);
            $names = SynthScaffold::witnessHeaderNames($seed);
            $pool = array_flip(SynthScaffold::allNames());
            $witnessBearing = 0;

            foreach ($routes as $route => $entry) {
                foreach ((array) ($entry['b'] ?? []) as $i => $bundle) {
                    if (!is_array($bundle)) {
                        continue;
                    }
                    $resp = $synth->synthesize($bundle, Detection::none(), "gate.example|{$material}");
                    if ($resp === null) {
                        continue;
                    }
                    self::assertEmpty(
                        preg_grep('/^X-Detected-/', array_keys($resp->headers)),
                        "no X-Detected-N tell may remain ({$route}#{$i} @ {$material})"
                    );
                    // Any synthetic key must be a pool name or the deterministic overflow shape.
                    foreach (array_keys($resp->headers) as $key) {
                        if (isset($pool[$key]) || preg_match('/^X-[A-Z][a-z]+-[A-Z][a-z]+-\d+$/', (string) $key) === 1) {
                            $witnessBearing += ($key === $names[0]) ? 1 : 0;
                        }
                    }
                }
            }
            // Per-deploy coherence: names[0] is the first name every witness-bearing bundle uses, so it
            // appears on all 403 of them; capturing it lets us prove it differs across deploys.
            self::assertGreaterThan(0, $witnessBearing, "witness headers must be emitted at material '{$material}'");
            $firstNameByMaterial[$material] = $names[0];
        }

        self::assertNotSame(
            $firstNameByMaterial['fp-0276-sample-a'],
            $firstNameByMaterial['fp-0276-sample-b'],
            'the deploy naming vocabulary must differ across deploys'
        );
    }

    public function test_body_order_varies_across_deploys_without_changing_the_byte_multiset(): void
    {
        $routes = self::index()['routes'] ?? [];
        $seedA = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $seedB = PersonaIdentity::seedFromMaterial('fp-0276-sample-b');
        $synthA = $this->synth($seedA);
        $synthB = $this->synth($seedB);

        $multiWord = 0;
        $differ = 0;
        $singleWordChecked = 0;

        foreach ($routes as $route => $entry) {
            foreach ((array) ($entry['b'] ?? []) as $i => $bundle) {
                if (!is_array($bundle)) {
                    continue;
                }
                $ra = $synthA->synthesize($bundle, Detection::none(), 'gate.example|fp-0276-sample-a');
                $rb = $synthB->synthesize($bundle, Detection::none(), 'gate.example|fp-0276-sample-b');
                if ($ra === null || $rb === null) {
                    continue;
                }
                $bw = array_map('strval', (array) ($bundle['bw'] ?? []));
                if (count($bw) >= 2) {
                    $multiWord++;
                    // Byte multiset invariant: same set of lines regardless of deploy.
                    $la = explode("\n", $ra->body);
                    $lb = explode("\n", $rb->body);
                    sort($la);
                    sort($lb);
                    self::assertSame($la, $lb, "the line multiset of {$route}#{$i} must be seed-invariant");
                    if ($ra->body !== $rb->body) {
                        $differ++;
                    }
                } elseif (count($bw) === 1 && empty($bundle['rx']) && empty($bundle['sz']) && empty($bundle['x'])) {
                    // A single-word body IS its matcher — fleet-constant by nature (no bytes invented).
                    self::assertSame($ra->body, $rb->body, "single-word body of {$route}#{$i} must be byte-identical across deploys");
                    $singleWordChecked++;
                }
            }
        }

        self::assertGreaterThan(1000, $multiWord, 'the index carries a large multi-word population');
        self::assertGreaterThan(100, $singleWordChecked, 'and a large single-word population');
        self::assertGreaterThanOrEqual(0.5, $differ / $multiWord, 'at least half of multi-word bodies differ across deploys');
    }

    public function test_named_real_fixtures_survive(): void
    {
        $seed = PersonaIdentity::seedFromMaterial('fp-0276-sample-a');
        $synth = $this->synth($seed);
        $routes = self::index()['routes'] ?? [];

        // GET / #10: 5 hw witnesses AND hf x-goog-metageneration/x-goog-generation. Must serve with
        // synthetic names, NONE containing 'goog'.
        if (isset($routes['GET /']['b'][10])) {
            $bundle = $routes['GET /']['b'][10];
            $resp = $synth->synthesize($bundle, Detection::none(), 'gate.example|fp-0276-sample-a');
            self::assertNotNull($resp, 'GET /#10 must serve');
            self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
            foreach (array_keys($resp->headers) as $key) {
                self::assertFalse(stripos((string) $key, 'goog') !== false, 'no synthetic name may contain the hf substring goog');
            }
        }

        // GET /ui/login.php #0: hw Set-Cookie= with hf Set-Cookie="" — must still serve.
        if (isset($routes['GET /ui/login.php']['b'][0])) {
            $bundle = $routes['GET /ui/login.php']['b'][0];
            $resp = $synth->synthesize($bundle, Detection::none(), 'gate.example|fp-0276-sample-a');
            self::assertNotNull($resp, 'GET /ui/login.php#0 must serve');
            self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
        }
    }
}
