<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Detection;
use Funnypot\Response\BundleValidator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\EmulatorRegistry;
use Funnypot\Response\EndpointEmulator;
use Funnypot\Response\RouteTemplateEmulator;
use Funnypot\Response\RouteTemplateSet;
use Funnypot\Response\Style;
use Funnypot\Synthesis\ResponseSynthesizer;
use PHPUnit\Framework\TestCase;

/**
 * The synthetic `X-Detected-N` header (no real server sends it) is a fingerprint tell.
 * On the rich path it must be emitted ONLY when the merged emulator/template header block
 * does not already carry the bundle's hw witness — never in addition to a believable real
 * header that already satisfies it. These tests pin both directions on the shared code
 * path so a template header that carries the witness suppresses the synthetic, while a
 * bundle whose witness is absent from every real header still keeps its synthetic (else it
 * would silently regress from rich enrich to minimal synthesis).
 */
final class XDetectedSuppressionTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    private function emulatorSynth(): ResponseSynthesizer
    {
        $set = RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');

        return new ResponseSynthesizer(new EmulatorRegistry([new RouteTemplateEmulator($set)]), Style::REALISTIC);
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

    // ---- Group A: a real template header carries the witness → no synthetic tell ----

    public function test_iceflow_log_real_server_header_suppresses_x_detected(): void
    {
        // GET /log/access.log #0: hw = [text/plain, ICEFLOW]. The route template supplies
        // Content-Type: text/plain and Server: ICEFLOW-VPN/2.4.1, so both witnesses live in
        // real headers and no X-Detected-N should remain on the enriched response.
        $bundle = $this->bundle('GET /log/access.log', 0);

        $resp = $this->emulatorSynth()->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp, 'the iceflow log bundle must be servable via the emulator');
        self::assertStringContainsString('ICEFLOW', $resp->headers['Server'] ?? '', 'the coherent ICEFLOW banner must be served');
        self::assertEmpty(
            preg_grep('/^X-Detected-/', array_keys($resp->headers)),
            'a real header carrying the witness must suppress the synthetic X-Detected tell'
        );
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    // ---- Group C: no real header carries the witness → synthetic stays (no regression) ----

    public function test_xinference_models_missing_witness_still_gets_x_detected(): void
    {
        // GET /v1/models #0: hw = [application/json, uvicorn]. The template carries
        // Content-Type: application/json but nothing carrying `uvicorn`, so the guarantee
        // (re-evaluated on the merged block) must still inject X-Detected for uvicorn — else
        // this bundle would fall back from the rich body to minimal synthesis.
        $bundle = $this->bundle('GET /v1/models', 0);

        $synth = $this->emulatorSynth();
        $resp = $synth->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp, 'the xinference models bundle must be servable via the emulator');

        $detected = preg_grep('/^X-Detected-/', array_keys($resp->headers));
        self::assertNotEmpty($detected, 'a witness absent from every real header must still get a synthetic');
        self::assertContains('uvicorn', $resp->headers, 'some X-Detected-N must carry the uvicorn witness');

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
    private function stubSynth(string $marker, string $body, array $overrideHeaders): ResponseSynthesizer
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

        return new ResponseSynthesizer(new EmulatorRegistry([$emulator]), Style::REALISTIC);
    }

    public function test_unit_template_header_with_witness_suppresses_synthetic(): void
    {
        // Non-Content-Type hw witness WIDGET, carried by a template Server header → no synthetic.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['widget-suppress']];

        $resp = $this->stubSynth('widget-suppress', "gizmo-body\ngizmo", ['Server' => 'WIDGET/1.0'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        self::assertSame('WIDGET/1.0', $resp->headers['Server'] ?? null);
        self::assertEmpty(preg_grep('/^X-Detected-/', array_keys($resp->headers)));
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }

    public function test_unit_witness_missing_from_headers_gets_exactly_one_synthetic(): void
    {
        // Same witness WIDGET, but the template supplies only Content-Type → exactly one
        // X-Detected-1: WIDGET is injected.
        $bundle = ['s' => 200, 'hw' => ['WIDGET'], 'bw' => ['gizmo'], 't' => ['widget-inject']];

        $resp = $this->stubSynth('widget-inject', "gizmo-body\ngizmo", ['Content-Type' => 'text/plain'])
            ->synthesize($bundle, Detection::none(), 'seed');

        self::assertNotNull($resp);
        $detected = preg_grep('/^X-Detected-/', array_keys($resp->headers));
        self::assertCount(1, $detected, 'exactly one synthetic witness header');
        self::assertArrayHasKey('X-Detected-1', $resp->headers);
        self::assertSame('WIDGET', $resp->headers['X-Detected-1']);
        self::assertTrue(BundleValidator::satisfies($resp->body, $resp->headers, $bundle));
    }
}
