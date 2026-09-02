<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Detection;
use Funnypot\Core\Response\BundleValidator;
use Funnypot\Core\Response\EmulatedContent;
use Funnypot\Core\Response\EmulatorRegistry;
use Funnypot\Core\Response\EndpointEmulator;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\Synthesis\SynthScaffold;
use PHPUnit\Framework\TestCase;

/**
 * The synthetic witness header (no real server sends one) is a fingerprint tell. FP-0281 renamed it
 * from the fleet-constant, self-identifying `X-Detected-N` to a per-deploy, semantics-free
 * `X-<First>-<Suffix>` from SynthScaffold — so the tests pin the seeded NAME, not the old literal. Two
 * invariants remain on the shared code path: a real template/bundle header carrying the bundle's hw
 * witness SUPPRESSES the synthetic (an enriched response is not also stamped with a tell); and a
 * witness absent from every real header still GETS one (else the response silently regresses from rich
 * enrichment to minimal synthesis). The witness VALUE is untouched — only the header NAME varies.
 */
final class XDetectedSuppressionTest extends TestCase
{
    /** An explicit deploy seed so the tests pin the seeded name, not a render-seed-derived one. */
    private const SEED = 4242;
    private const ALT_SEED = 4243;

    /** @var array<string,mixed>|null */
    private static $index = null;

    /** @return list<string> the deploy's ordered witness-header names for self::SEED */
    private function names(int $seed = self::SEED): array
    {
        return SynthScaffold::witnessHeaderNames($seed);
    }

    private function emulatorSynth(int $seed = self::SEED): ResponseSynthesizer
    {
        $set = RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');

        return new ResponseSynthesizer(new EmulatorRegistry([new RouteTemplateEmulator($set)]), Style::REALISTIC, null, null, $seed);
    }

    /**
     * @return array<string,mixed>
     */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    /**
     * @return array<string,mixed>
     */
    private function bundle(string $route, int $i): array
    {
        $routes = self::index()['routes'] ?? [];
        self::assertArrayHasKey($route, $routes, "route {$route} is not in the compiled index");
        self::assertArrayHasKey($i, $routes[$route]['b'] ?? [], "bundle #{$i} is not present at {$route}");

        return $routes[$route]['b'][$i];
    }

    /** Synthetic keys on a response: those matching a pool name or the overflow shape. */
    private function syntheticKeys(array $headers): array
    {
        $pool = array_flip(SynthScaffold::allNames());

        return array_values(array_filter(array_keys($headers), static function ($k) use ($pool): bool {
            return isset($pool[(string) $k]) || preg_match('/^X-[A-Z][a-z]+-[A-Z][a-z]+-\d+$/', (string) $k) === 1;
        }));
    }

    // ---- Group A: a real template header carries the witness → no synthetic tell ----

    public function test_iceflow_log_real_server_header_suppresses_synthetic(): void
    {
        // GET /log/access.log #0: hw = [text/plain, ICEFLOW]. The route template supplies
        // Content-Type: text/plain and Server: ICEFLOW-VPN/2.4.1, so both witnesses live in
        // real headers and no synthetic witness header should remain on the enriched response.
        $bundle = $this->bundle('GET /log/access.log', 0);

        $resp = $this->emulatorSynth()->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp, 'the iceflow log bundle must be servable via the emulator');
        self::assertStringContainsString('ICEFLOW', $resp->headers['Server'] ?? '', 'the coherent ICEFLOW banner must be served');
        self::assertEmpty($this->syntheticKeys($resp->headers), 'a real header carrying the witness must suppress the synthetic tell');
        self::assertEmpty(preg_grep('/^X-Detected-/', array_keys($resp->headers)), 'the old X-Detected-N literal must never appear');
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    // ---- Group C: no real header carries the witness → synthetic stays (no regression) ----

    public function test_xinference_models_missing_witness_still_gets_a_synthetic(): void
    {
        // GET /v1/models #0: hw = [application/json, uvicorn]. The template carries
        // Content-Type: application/json but nothing carrying `uvicorn`, so the guarantee
        // (re-evaluated on the merged block) must still inject a synthetic for uvicorn — else
        // this bundle would fall back from the rich body to minimal synthesis.
        $bundle = $this->bundle('GET /v1/models', 0);
        $names = $this->names();

        $synth = $this->emulatorSynth();
        $resp = $synth->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp, 'the xinference models bundle must be servable via the emulator');

        $synthetic = $this->syntheticKeys($resp->headers);
        self::assertCount(1, $synthetic, 'a witness absent from every real header must still get exactly one synthetic');
        self::assertSame($names[0], $synthetic[0], 'the synthetic uses the deploy first name');
        self::assertSame('uvicorn', $resp->headers[$names[0]], 'the synthetic carries the uvicorn witness');
        self::assertEmpty(preg_grep('/^X-Detected-/', array_keys($resp->headers)), 'the old X-Detected-N literal must never appear');

        // The RICH template body is served, not minimal synth: a model id only the authored
        // template body carries, and no recorded fall-back reason.
        self::assertStringContainsString('text-embedding-3-large', $resp->body, 'the rich template body must be served (not minimal synth)');
        self::assertSame('', $synth->lastSkipReason());

        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    // ---- Unit fixtures: both directions on the shared path, independent of corpus drift ----

    /**
     * A stub emulator that recognises a fixture bundle by a marker in its `t` list and returns
     * a fixed body plus header overrides — lets us exercise the merge/overlay/guarantee path
     * without depending on any shipped route template.
     */
    private function stubSynth(string $marker, string $body, array $overrideHeaders, int $seed = self::SEED): ResponseSynthesizer
    {
        $emulator = new class($marker, $body, $overrideHeaders) implements EndpointEmulator {
            /** @var string */
            private $marker;
            /** @var string */
            private $body;
            /** @var array<string,string> */
            private $headers;

            /** @param array<string,string> $headers */
            public function __construct(string $marker, string $body, array $headers)
            {
                $this->marker = $marker;
                $this->body = $body;
                $this->headers = $headers;
            }

            public function supports(array $bundle): bool
            {
                return in_array($this->marker, array_map('strval', (array) ($bundle['t'] ?? [])), true);
            }

            public function render(array $bundle, string $style, int $seed): ?EmulatedContent
            {
                return new EmulatedContent($this->body, $this->headers);
            }
        };

        return new ResponseSynthesizer(new EmulatorRegistry([$emulator]), Style::REALISTIC, null, null, $seed);
    }

    public function test_unit_template_header_with_witness_suppresses_synthetic(): void
    {
        // Non-Content-Type hw witness WIDGET, carried by a template Server header → no synthetic.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['widget-suppress']];

        $resp = $this->stubSynth('widget-suppress', "gizmo-body\ngizmo", ['Server' => 'WIDGET/1.0'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        self::assertSame('WIDGET/1.0', $resp->headers['Server'] ?? null);
        self::assertEmpty($this->syntheticKeys($resp->headers));
        self::assertEmpty(preg_grep('/^X-Detected-/', array_keys($resp->headers)));
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_witness_missing_from_headers_gets_exactly_one_synthetic(): void
    {
        // Same witness WIDGET, but the template supplies only Content-Type → exactly one synthetic under
        // the deploy first name, carrying WIDGET.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['widget-inject']];
        $names = $this->names();

        $resp = $this->stubSynth('widget-inject', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        $synthetic = $this->syntheticKeys($resp->headers);
        self::assertCount(1, $synthetic, 'exactly one synthetic witness header');
        self::assertSame($names[0], $synthetic[0]);
        self::assertSame('WIDGET', $resp->headers[$names[0]]);
        self::assertEmpty(preg_grep('/^X-Detected-/', array_keys($resp->headers)), 'never the old X-Detected-N literal');
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_hf_forbidden_name_is_skipped_for_the_next_pool_name(): void
    {
        // (a) The bundle's hf forbids the substring of the FIRST pool name, so the witness must land
        // under the SECOND name and the bundle must still serve (else hf would skip it — a regression).
        $names = $this->names();
        $forbidden = strtolower(substr($names[0], 2, 4)); // e.g. 'upst' from X-Upstream-*
        self::assertStringNotContainsStringIgnoringCase($forbidden, $names[1], 'the 4-char cut must not also hit the second name');

        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'hf' => [$forbidden], 'bw' => ['gizmo'], 't' => ['hf-skip']];

        $resp = $this->stubSynth('hf-skip', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp, 'the bundle must still serve with the first name skipped');
        self::assertArrayNotHasKey($names[0], $resp->headers, 'the hf-colliding first name must be skipped');
        self::assertSame('WIDGET', $resp->headers[$names[1]] ?? null, 'the witness lands under the second name');
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_existing_header_key_is_never_overwritten(): void
    {
        // (b) A template header already occupying the first pool name → the witness lands under the
        // second, and the template value is untouched.
        $names = $this->names();
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['collide']];

        $resp = $this->stubSynth('collide', "gizmo-body\ngizmo", [$names[0] => 'real-value', 'Content-Type' => 'text/plain'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        self::assertSame('real-value', $resp->headers[$names[0]], 'the template value must not be overwritten');
        self::assertSame('WIDGET', $resp->headers[$names[1]] ?? null, 'the witness lands under the next free name');
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_two_witnesses_take_two_names_in_order(): void
    {
        // (c) Two missing witnesses → the first two names, in the deploy's order.
        $names = $this->names();
        $bundle = ['s' => 200, 'hw' => ['WIDGET', 'GADGET'], 'bw' => ['gizmo'], 't' => ['two']];

        $resp = $this->stubSynth('two', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        self::assertSame('WIDGET', $resp->headers[$names[0]] ?? null);
        self::assertSame('GADGET', $resp->headers[$names[1]] ?? null);
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_synthetic_names_differ_across_deploys(): void
    {
        // (d) The same bundle through two deploy seeds → different synthetic key names.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['xdeploy']];

        $a = $this->stubSynth('xdeploy', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'], self::SEED)
            ->synthesize($bundle, Detection::none(), 'seed');
        $b = $this->stubSynth('xdeploy', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'], self::ALT_SEED)
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($this->names(self::SEED)[0], $this->syntheticKeys($a->headers)[0]);
        self::assertSame($this->names(self::ALT_SEED)[0], $this->syntheticKeys($b->headers)[0]);
        self::assertNotSame($this->syntheticKeys($a->headers)[0], $this->syntheticKeys($b->headers)[0], 'the synthetic name must vary across deploys');
    }

    public function test_unit_null_deploy_seed_falls_back_deterministically_to_the_render_seed(): void
    {
        // (e) A synthesizer built without a deploy seed (never production) keys the name off the render
        // seed via crc32($seed)&0x7fffffff — deterministic per persona-seed string, not per-request.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo']];
        $expected = SynthScaffold::witnessHeaderNames(crc32('seed') & 0x7fffffff)[0];

        $synth = new ResponseSynthesizer(null);
        $r1 = $synth->synthesize($bundle, Detection::none(), 'seed');
        $r2 = $synth->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($r1);
        self::assertNotNull($r2);
        self::assertSame($this->syntheticKeys($r1->headers), $this->syntheticKeys($r2->headers), 'deterministic per persona-seed string');
        self::assertSame($expected, $this->syntheticKeys($r1->headers)[0]);
        self::assertSame('WIDGET', $r1->headers[$expected] ?? null);
    }
}
