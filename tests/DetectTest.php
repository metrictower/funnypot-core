<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

final class DetectTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function inverter(): Honeypot
    {
        // Default config: inert (detect only).
        return new Honeypot($this->store());
    }

    private function respondInverter(): Honeypot
    {
        return new Honeypot($this->store(), new Config(
            'respond',                                                   // mode
            static function (RequestContext $r): bool { return true; }   // gate
        ));
    }

    public function test_known_probe_is_detected_with_metadata(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/.git/config'));

        self::assertTrue($d->matched);
        self::assertFalse($d->isEmpty());
        self::assertSame(['git-config'], $d->templateIds());
        self::assertSame('medium', $d->highestSeverity);
        self::assertContains('git', $d->tags());
        self::assertSame('GET /.git/config', $d->clusterKey);
    }

    public function test_miss_returns_none(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/totally/legit/page'));

        self::assertFalse($d->matched);
        self::assertTrue($d->isEmpty());
        self::assertSame([], $d->templateIds());
        self::assertSame('', $d->clusterKey);
    }

    public function test_post_falls_back_to_get_bundle(): void
    {
        // R1: the GET-only index still answers a POST probe for the same path (a third of
        // scanner probes are POST). It resolves to the GET bundle's templates.
        $d = $this->inverter()->detect(new RequestContext('POST', '/.git/config'));

        self::assertTrue($d->matched);
        self::assertSame(['git-config'], $d->templateIds());
    }

    public function test_method_coverage_answers_options_trace_on_a_covered_path(): void
    {
        // OPTIONS/TRACE/PROPFIND do NOT fall back to GET (a real server answers them differently),
        // but a servable compiled path now gets bounded method coverage (FP-0011): the request is
        // recognized as a method-discovery probe carrying a stable synthetic id, not a route match.
        self::assertSame(['http-method-options'], $this->inverter()->detect(new RequestContext('OPTIONS', '/.git/config'))->templateIds());
        self::assertSame(['http-method-trace'], $this->inverter()->detect(new RequestContext('TRACE', '/.git/config'))->templateIds());
        self::assertSame(['http-method-propfind'], $this->inverter()->detect(new RequestContext('PROPFIND', '/.git/config'))->templateIds());
        // A genuinely unknown path stays a miss — coverage never invents a method surface there.
        self::assertFalse($this->inverter()->detect(new RequestContext('OPTIONS', '/totally-unknown'))->matched);
        self::assertFalse($this->inverter()->detect(new RequestContext('TRACE', '/totally-unknown'))->matched);
    }

    public function test_query_string_is_ignored_for_routing(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/webpack.config.js', 'v=1'));

        self::assertTrue($d->matched);
        self::assertSame(['webpack-config'], $d->templateIds());
    }

    public function test_full_target_in_path_field_still_routes(): void
    {
        // A caller that shoves the whole request-target into path still resolves.
        $d = $this->inverter()->detect(new RequestContext('GET', '/webpack.config.js?v=1'));

        self::assertTrue($d->matched);
        self::assertSame(['webpack-config'], $d->templateIds());
    }

    public function test_multi_path_template_routes_from_either_path(): void
    {
        $a = $this->inverter()->detect(new RequestContext('GET', '/npm-debug.log'));
        $b = $this->inverter()->detect(new RequestContext('GET', '/assets/npm-debug.log'));

        self::assertSame(['npm-debug-log'], $a->templateIds());
        self::assertSame(['npm-debug-log'], $b->templateIds());
    }

    public function test_trailing_slash_variant_resolves(): void
    {
        // R1: /config/ is the compiled key; a probe for /config (no slash) falls back to it.
        self::assertTrue($this->inverter()->detect(new RequestContext('GET', '/config/'))->matched);
        self::assertTrue($this->inverter()->detect(new RequestContext('GET', '/config'))->matched);
        // A genuinely unknown path still misses.
        self::assertFalse($this->inverter()->detect(new RequestContext('GET', '/totally-unknown'))->matched);
    }

    public function test_severity_ceiling_helper(): void
    {
        self::assertSame('high', Detection::ceilingSeverity('low', 'high'));
        self::assertSame('critical', Detection::ceilingSeverity('critical', 'medium'));
        self::assertSame('medium', Detection::ceilingSeverity('medium', 'info'));
    }

    public function test_respond_synthesizes_a_satisfying_response(): void
    {
        // In respond mode with an open gate, respond() builds a fake from the chosen
        // bundle: every required body word present, no forbidden substring, the bundle
        // status, and a record of which templates it satisfies.
        $response = $this->respondInverter()->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($response);
        self::assertSame(200, $response->status);
        self::assertStringContainsString('[core]', $response->body);
        self::assertStringNotContainsStringIgnoringCase('<html', $response->body);
        self::assertStringNotContainsStringIgnoringCase('<body', $response->body);
        self::assertArrayHasKey('Content-Type', $response->headers);
        self::assertSame(['git-config'], $response->satisfies->templateIds());
    }

    public function test_respond_returns_null_on_miss(): void
    {
        self::assertNull($this->respondInverter()->respond(new RequestContext('GET', '/totally/legit/page')));
    }

    public function test_respond_is_inert_under_default_config(): void
    {
        // A default install is detect-only: respond serves nothing even on a known path.
        self::assertNull($this->inverter()->respond(new RequestContext('GET', '/.git/config')));
    }

    public function test_respond_requires_an_open_gate(): void
    {
        $inv = new Honeypot($this->store(), new Config('respond'));

        // Gate defaults closed (no predicate) -> no fake served.
        self::assertNull($inv->respond(new RequestContext('GET', '/.git/config')));
    }

    public function test_trusted_bypass_suppresses_response(): void
    {
        $inv = new Honeypot($this->store(), new Config(
            'respond',                                                   // mode
            static function (RequestContext $r): bool { return true; },  // gate
            'matched-only',                                              // pathScope
            null,                                                        // personaSeed
            'coherent',                                                  // personaBreadth
            \Funnypot\Core\Response\Style::MINIMAL,                           // responseStyle
            'high',                                                      // severityCeiling
            65536,                                                       // maxBodyBytes
            0,                                                           // latencyMs
            0,                                                           // latencyJitterMs
            false,                                                       // attackEmulation
            static function (RequestContext $r): bool { return true; }   // trustedBypass
        ));

        self::assertNull($inv->respond(new RequestContext('GET', '/.git/config')));
    }
}
