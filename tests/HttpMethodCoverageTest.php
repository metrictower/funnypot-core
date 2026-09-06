<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0011 — bounded HTTP method coverage. A servable compiled path answers OPTIONS/TRACE/PROPFIND
 * method-discovery probes with a closed 204/405 + canonical Allow, without a per-path template and
 * without ever shadowing an exact authored method route, a real host route, or an attack/param
 * ownership. Nothing is derived from the request bytes, so the responses carry no reflection.
 */
final class HttpMethodCoverageTest extends TestCase
{
    /**
     * @param array<string,array<int,array<string,mixed>>> $routes  key => bundles
     * @param array<string,array<string,mixed>>            $templates
     */
    private function store(array $routes, array $templates = ['t-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A']]): PhpArrayStore
    {
        return new PhpArrayStore(['schema' => 1, 'manifest' => [], 'templates' => $templates, 'routes' => $routes]);
    }

    /** One servable low bundle over template id $t. */
    private function bundle(string $t = 't-a', int $sig = 0, string $sev = 'low'): array
    {
        return [['s' => 200, 'bw' => ['X'], 'nf' => [], 'h' => [], 'pid' => 'p', 'sev' => $sev, 'sig' => $sig, 't' => [$t]]];
    }

    /**
     * @param string[] $exclude
     * @param string[] $ignore
     */
    private function config(array $exclude = [], array $ignore = [], ?\Closure $gate = null, bool $nuclei = true, string $ceiling = 'high'): Config
    {
        return new Config(
            'respond',
            $gate ?? static function (RequestContext $r): bool { return true; },
            'matched-only', null, 'coherent', Style::MINIMAL, $ceiling, 65536, 0, 0,
            false, null, null, null, '',
            $exclude, $nuclei, null, null, null, null, null, $ignore
        );
    }

    private function engine(array $routes, array $exclude = [], array $ignore = []): Honeypot
    {
        return new Honeypot($this->store($routes), $this->config($exclude, $ignore));
    }

    /** classify() against an empty profile — the detect-mode view. */
    private function classify(Honeypot $e, string $method, string $path, string $query = '', array $headers = [], ?string $body = null, string $host = ''): Verdict
    {
        return $e->classify(new RequestContext($method, $path, $query, $headers, $body, $host), SiteProfile::empty());
    }

    // --- Allow-list derivation ---------------------------------------------------------------------

    public function test_get_only_path_advertises_get_head_post_options(): void
    {
        // HEAD/POST ride the documented GET fallback (no exact HEAD/POST key), OPTIONS is appended.
        $r = $this->engine(['GET /g' => ['b' => $this->bundle()]])->respond(new RequestContext('OPTIONS', '/g'));

        self::assertNotNull($r);
        self::assertSame(204, $r->status);
        self::assertSame('GET, HEAD, POST, OPTIONS', $r->headers['Allow']);
    }

    public function test_put_only_path_advertises_only_put_and_options(): void
    {
        // PUT has no GET fallback; GET/HEAD/POST are absent, TRACE/PURGE/DELETE never appear unrequested.
        $r = $this->engine(['PUT /p' => ['b' => $this->bundle()]])->respond(new RequestContext('OPTIONS', '/p'));

        self::assertNotNull($r);
        self::assertSame('PUT, OPTIONS', $r->headers['Allow']);
    }

    public function test_canonical_order_is_fixed(): void
    {
        // Everything present at once: the Allow list is emitted in the fixed canonical order, not
        // store/probe order.
        $routes = [
            'GET /a' => ['b' => $this->bundle()],
            'POST /a' => ['b' => $this->bundle()],
            'PUT /a' => ['b' => $this->bundle()],
            'DELETE /a' => ['b' => $this->bundle()],
            'TRACE /a' => ['b' => $this->bundle()],
            'PURGE /a' => ['b' => $this->bundle()],
        ];
        $r = $this->engine($routes)->respond(new RequestContext('PROPFIND', '/a'));

        self::assertNotNull($r);
        self::assertSame('GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PURGE', $r->headers['Allow']);
    }

    public function test_exact_but_ineligible_head_blocks_the_get_fallback(): void
    {
        // An exact HEAD key that is excluded from serving does NOT silently borrow GET — it blocks
        // the fallback (resolve-then-decline), so HEAD drops out of Allow while POST still falls back.
        $routes = [
            'GET /g' => ['b' => $this->bundle('t-a')],
            'HEAD /g' => ['b' => $this->bundle('t-head')],
        ];
        $templates = [
            't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
            't-head' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'H'],
        ];
        $engine = new Honeypot($this->store($routes, $templates), $this->config(['t-head']));

        $r = $engine->respond(new RequestContext('OPTIONS', '/g'));
        self::assertNotNull($r);
        self::assertSame('GET, POST, OPTIONS', $r->headers['Allow']);
    }

    // --- wire semantics ----------------------------------------------------------------------------

    public function test_options_is_a_bare_204(): void
    {
        $r = $this->engine(['GET /g' => ['b' => $this->bundle()]])->respond(new RequestContext('OPTIONS', '/g'));

        self::assertNotNull($r);
        self::assertSame(204, $r->status);
        self::assertSame('', $r->body);
        self::assertArrayNotHasKey('Content-Type', $r->headers);
        self::assertArrayNotHasKey('Content-Length', $r->headers);
        self::assertArrayNotHasKey('Transfer-Encoding', $r->headers);
        // The emitter view: RFC 9110 forbids Content-Length on 204, so none is synthesized either.
        $cl = array_filter(ResponseEmitter::headerLines($r), static function (array $e): bool {
            return stripos($e[0], 'Content-Length:') === 0;
        });
        self::assertCount(0, $cl);
    }

    /** @dataProvider unsupportedVerbs */
    public function test_trace_and_propfind_are_empty_405_with_content_length_zero(string $method): void
    {
        $r = $this->engine(['GET /g' => ['b' => $this->bundle()]])->respond(new RequestContext($method, '/g'));

        self::assertNotNull($r);
        self::assertSame(405, $r->status);
        self::assertSame('', $r->body);
        self::assertSame('0', $r->headers['Content-Length']);
        self::assertArrayNotHasKey('Content-Type', $r->headers);
        // Exactly one Content-Length line through the emitter — no doubled synthesis.
        $cl = array_filter(ResponseEmitter::headerLines($r), static function (array $e): bool {
            return stripos($e[0], 'Content-Length:') === 0;
        });
        self::assertCount(1, $cl);
        self::assertSame('Content-Length: 0', array_values($cl)[0][0]);
    }

    /** @return array<string,array{0:string}> */
    public function unsupportedVerbs(): array
    {
        return ['TRACE' => ['TRACE'], 'PROPFIND' => ['PROPFIND']];
    }

    public function test_no_dav_or_cors_headers_are_ever_emitted(): void
    {
        $r = $this->engine(['GET /g' => ['b' => $this->bundle()]])->respond(new RequestContext('PROPFIND', '/g'));

        self::assertNotNull($r);
        foreach (['DAV', 'MS-Author-Via', 'Access-Control-Allow-Origin', 'Access-Control-Allow-Methods', 'Location'] as $h) {
            self::assertArrayNotHasKey($h, $r->headers, "$h must never appear");
        }
    }

    // --- variant convergence and boundaries --------------------------------------------------------

    public function test_slash_and_case_variants_converge_on_one_canonical_path(): void
    {
        $engine = $this->engine(['GET /foo' => ['b' => $this->bundle()]]);

        foreach (['/foo', '/foo/', '/FOO'] as $path) {
            $r = $engine->respond(new RequestContext('OPTIONS', $path));
            self::assertNotNull($r, $path);
            self::assertSame(204, $r->status, $path);
            self::assertSame('GET, HEAD, POST, OPTIONS', $r->headers['Allow'], $path);
        }
    }

    public function test_variants_are_not_unioned_across_distinct_resources(): void
    {
        // GET /Foo and POST /foo are different resources. The first path variant with a capability
        // wins and its verbs are computed only there — never a union of both.
        $routes = [
            'GET /Foo' => ['b' => $this->bundle()],
            'POST /foo' => ['b' => $this->bundle()],
        ];
        $engine = $this->engine($routes);

        // Incoming /Foo resolves at /Foo: POST here is the GET fallback, not the exact POST /foo.
        $upper = $engine->respond(new RequestContext('OPTIONS', '/Foo'));
        self::assertNotNull($upper);
        self::assertSame('GET, HEAD, POST, OPTIONS', $upper->headers['Allow']);

        // Incoming /foo resolves at /foo: only the exact POST, no GET fallback (no GET /foo key).
        $lower = $engine->respond(new RequestContext('OPTIONS', '/foo'));
        self::assertNotNull($lower);
        self::assertSame('POST, OPTIONS', $lower->headers['Allow']);
    }

    public function test_unknown_path_gets_no_coverage(): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);

        self::assertNull($engine->respond(new RequestContext('OPTIONS', '/unknown')));
        self::assertTrue($this->classify($engine, 'OPTIONS', '/unknown')->detection->isEmpty());
    }

    public function test_asterisk_form_options_is_never_covered(): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);

        $v = $this->classify($engine, 'OPTIONS', '*');
        self::assertSame(Verdict::CLEAN, $v->classification);
        self::assertNull($v->fakeHandle);
        self::assertNull($engine->respond(new RequestContext('OPTIONS', '*')));
    }

    /** @dataProvider uncoveredVerbs */
    public function test_verbs_outside_the_three_get_no_coverage(string $method): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);

        $v = $this->classify($engine, $method, '/g');
        self::assertNull($v->fakeHandle, "$method must not gain a method handle");
    }

    /** @return array<string,array{0:string}> */
    public function uncoveredVerbs(): array
    {
        return ['PUT' => ['PUT'], 'DELETE' => ['DELETE'], 'PATCH' => ['PATCH'], 'CONNECT' => ['CONNECT']];
    }

    // --- classification contract -------------------------------------------------------------------

    public function test_generic_options_root_is_clean_with_a_method_handle(): void
    {
        $v = $this->classify($this->engine(['GET /' => ['b' => $this->bundle('t-a', 1)]]), 'OPTIONS', '/');

        self::assertSame(Verdict::CLEAN, $v->classification);
        self::assertNotNull($v->fakeHandle);
        self::assertSame(FakeHandle::KIND_METHOD, $v->fakeHandle->kind);
        self::assertSame('OPTIONS /', $v->fakeHandle->key);
        self::assertSame(['http-method-options'], $v->detection->templateIds());
    }

    public function test_options_root_negotiates_without_a_probe_signature(): void
    {
        // The CLEAN exemption: a 204 + honest Allow is negotiation, so OPTIONS / serves on a
        // standalone honeypot even though a CLEAN GET / (route handle) would still need a signature.
        $engine = $this->engine(['GET /' => ['b' => $this->bundle('t-a', 1)]]);

        $options = $engine->respond(new RequestContext('OPTIONS', '/'));
        self::assertNotNull($options);
        self::assertSame(204, $options->status);

        self::assertNull($engine->respond(new RequestContext('GET', '/')), 'GET / route handle still needs a probe signature');
    }

    public function test_non_root_options_and_all_trace_propfind_are_scanner_probes(): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()], 'GET /' => ['b' => $this->bundle('t-a', 1)]]);

        self::assertSame(Verdict::SCANNER_PROBE, $this->classify($engine, 'OPTIONS', '/g')->classification);
        self::assertSame(Verdict::SCANNER_PROBE, $this->classify($engine, 'TRACE', '/g')->classification);
        self::assertSame(Verdict::SCANNER_PROBE, $this->classify($engine, 'PROPFIND', '/g')->classification);
        // TRACE / is method discovery even at root (only GET/HEAD root is an ordinary navigation).
        self::assertSame(Verdict::SCANNER_PROBE, $this->classify($engine, 'TRACE', '/')->classification);
    }

    public function test_exact_non_get_root_route_classifies_scanner_probe(): void
    {
        // A shipped non-GET root lure (here a POST / sig=1 stub) is method discovery, not navigation.
        $engine = $this->engine(['POST /' => ['b' => $this->bundle('t-a', 1)]]);
        self::assertSame(Verdict::SCANNER_PROBE, $this->classify($engine, 'POST', '/')->classification);
    }

    public function test_get_and_head_root_stay_clean(): void
    {
        $engine = $this->engine(['GET /' => ['b' => $this->bundle('t-a', 1)], 'HEAD /' => ['b' => $this->bundle('t-a', 1)]]);
        self::assertSame(Verdict::CLEAN, $this->classify($engine, 'GET', '/')->classification);
        self::assertSame(Verdict::CLEAN, $this->classify($engine, 'HEAD', '/')->classification);
    }

    // --- config eligibility gates ------------------------------------------------------------------

    public function test_corpus_off_uncovers_a_nuclei_route(): void
    {
        // nucleiReflection off drops the nuclei bundle, so its path has no eligible route left.
        $engine = new Honeypot($this->store(['GET /g' => ['b' => $this->bundle()]]), $this->config([], [], null, false));
        self::assertNull($engine->respond(new RequestContext('OPTIONS', '/g')));
        self::assertTrue($this->classify($engine, 'OPTIONS', '/g')->detection->isEmpty());
    }

    public function test_severity_ceiling_uncovers_an_over_ceiling_route(): void
    {
        $templates = ['t-crit' => ['sev' => 'critical', 'tags' => ['rce'], 'name' => 'C']];
        $routes = ['GET /g' => ['b' => $this->bundle('t-crit', 0, 'critical')]];
        $engine = new Honeypot($this->store($routes, $templates), $this->config([], [], null, true, 'high'));
        self::assertNull($engine->respond(new RequestContext('OPTIONS', '/g')));
    }

    public function test_ignore_removes_evidence_and_handle_by_id_and_by_tag(): void
    {
        foreach (['http-method-options', 'scanner-coverage', 'http-methods'] as $silenced) {
            $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]], [], [$silenced]);
            $v = $this->classify($engine, 'OPTIONS', '/g');
            self::assertSame(Verdict::CLEAN, $v->classification, $silenced);
            self::assertNull($v->fakeHandle, $silenced);
            self::assertNull($engine->respond(new RequestContext('OPTIONS', '/g')), $silenced);
        }
    }

    public function test_exclude_permits_detection_but_declines_synthesis(): void
    {
        // The ignore/exclude split: exclude keeps the SCANNER_PROBE detection but makes serving decline.
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]], ['http-method-trace']);

        $v = $this->classify($engine, 'TRACE', '/g');
        self::assertSame(Verdict::SCANNER_PROBE, $v->classification);
        self::assertFalse($v->detection->isEmpty());
        self::assertSame(['http-method-trace'], $v->detection->templateIds());

        self::assertNull($engine->respond(new RequestContext('TRACE', '/g')));
    }

    // --- real-route veto ---------------------------------------------------------------------------

    public function test_a_real_host_route_gets_no_generic_coverage(): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);
        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return $path === '/g';
        });

        $v = $engine->classify(new RequestContext('OPTIONS', '/g'), $profile);
        self::assertSame(Verdict::CLEAN, $v->classification);
        self::assertNull($v->fakeHandle);
    }

    public function test_synthesis_repeats_the_real_route_veto_on_the_canonical_path(): void
    {
        // A handle minted before a route went live must not shadow it at synthesis time.
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);
        $profile = new SiteProfile([], static function (string $method, string $path): bool {
            return $path === '/g';
        });

        self::assertNull($engine->synthesizeFromHandle(FakeHandle::method('OPTIONS /g'), $profile, 'seed'));
    }

    // --- handle validation and re-resolution -------------------------------------------------------

    public function test_method_handle_round_trips_and_forces_null_intent(): void
    {
        $h = FakeHandle::method('OPTIONS /g');
        $back = FakeHandle::fromArray($h->toArray());

        self::assertSame(FakeHandle::KIND_METHOD, $back->kind);
        self::assertSame('OPTIONS /g', $back->key);
        self::assertNull($back->paramIntent);
        self::assertEquals($h, FakeHandle::fromArray(json_decode(json_encode($h->toArray()), true)));
    }

    /** @dataProvider tamperedHandles */
    public function test_malformed_or_stale_handles_fail_to_null(FakeHandle $handle): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);

        self::assertNull($engine->synthesizeFromHandle($handle, SiteProfile::empty(), 'seed'));
    }

    /** @return array<string,array{0:FakeHandle}> */
    public function tamperedHandles(): array
    {
        return [
            'unsupported verb' => [FakeHandle::method('DELETE /g')],
            'asterisk path' => [FakeHandle::method('OPTIONS /*')],
            'unrooted path' => [FakeHandle::method('OPTIONS g')],
            'no space' => [FakeHandle::fromArray(['kind' => 'method', 'key' => 'OPTIONS'])],
            'stale uncovered path' => [FakeHandle::method('OPTIONS /gone')],
        ];
    }

    public function test_a_freshly_appeared_exact_route_declines_the_generic_fallback(): void
    {
        // The store now carries an exact OPTIONS /g route: the generic fallback must yield to it.
        $engine = $this->engine([
            'GET /g' => ['b' => $this->bundle()],
            'OPTIONS /g' => ['b' => $this->bundle()],
        ]);

        self::assertNull($engine->synthesizeFromHandle(FakeHandle::method('OPTIONS /g'), SiteProfile::empty(), 'seed'));
    }

    public function test_a_stale_handle_whose_route_was_excluded_declines(): void
    {
        // Handle minted while /g was covered; the operator has since excluded its only template.
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]], ['t-a']);

        self::assertNull($engine->synthesizeFromHandle(FakeHandle::method('OPTIONS /g'), SiteProfile::empty(), 'seed'));
    }

    // --- no reflection -----------------------------------------------------------------------------

    public function test_request_bytes_never_enter_the_response(): void
    {
        $engine = $this->engine(['GET /g' => ['b' => $this->bundle()]]);
        $sentinel = 'SENTINEL_REFLECT_ME';
        $r = $engine->respond(new RequestContext(
            'PROPFIND',
            '/g',
            'q=' . $sentinel,
            ['X-Probe' => $sentinel, 'Origin' => 'https://' . $sentinel, 'Access-Control-Request-Method' => $sentinel],
            '<propfind>' . $sentinel . '</propfind>',
            $sentinel . '.example'
        ));

        self::assertNotNull($r);
        self::assertStringNotContainsString($sentinel, $r->body);
        self::assertStringNotContainsString($sentinel, (string) $r->headers['Allow']);
        foreach ($r->headers as $name => $value) {
            self::assertStringNotContainsString($sentinel, $name . ': ' . (is_array($value) ? implode(',', $value) : $value));
        }
    }

    // --- a throwing host gate still fails closed ---------------------------------------------------

    public function test_a_throwing_gate_declines_a_method_response(): void
    {
        $engine = new Honeypot($this->store(['GET /g' => ['b' => $this->bundle()]]), $this->config([], [], static function (RequestContext $r): bool {
            throw new \RuntimeException('boom');
        }));

        self::assertNull($engine->respond(new RequestContext('OPTIONS', '/g')));
    }

    // --- against the production artifact ------------------------------------------------------------

    private function fullEngine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only', null, 'coherent', Style::MINIMAL, 'critical'));
    }

    public function test_shipped_trace_root_lure_stays_authored(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('TRACE', '/'));

        self::assertNotNull($r);
        self::assertSame(200, $r->status, 'the authored XST lure, not a generic 405');
        self::assertSame(['cross-site-tracing-xss'], $r->satisfies->templateIds());
    }

    public function test_shipped_options_optinmonster_lure_stays_authored(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('OPTIONS', '/wp-json/omapp/v1/support'));

        self::assertNotNull($r);
        self::assertSame(200, $r->status, 'the authored route, not a generic 204');
        self::assertSame(['CVE-2021-39341'], $r->satisfies->templateIds());
    }

    public function test_generic_fallback_covers_a_representative_corpus_route(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('OPTIONS', '/.git/config'));

        self::assertNotNull($r);
        self::assertSame(204, $r->status);
        self::assertSame(['http-method-options'], $r->satisfies->templateIds());
        self::assertStringContainsString('GET', (string) $r->headers['Allow']);
    }

    public function test_outcome_is_served_for_a_covered_method(): void
    {
        $observer = new class implements \Funnypot\Core\Observer {
            /** @var string[] */
            public $outcomes = [];
            public function onDetection(RequestContext $r, \Funnypot\Core\Detection $d): void {}
            public function shouldRespond(RequestContext $r, \Funnypot\Core\Detection $d): bool { return true; }
            public function onOutcome(RequestContext $r, ?SynthesizedResponse $resp, string $reason): void { $this->outcomes[] = $reason; }
        };
        $engine = new Honeypot($this->store(['GET /g' => ['b' => $this->bundle()]]), $this->config(), $observer);
        $engine->respond(new RequestContext('OPTIONS', '/g'));

        self::assertSame([Outcome::SERVED], $observer->outcomes);
    }
}
