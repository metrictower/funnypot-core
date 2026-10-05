<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use Funnypot\Core\XssProbe;
use PHPUnit\Framework\TestCase;

/**
 * FP-0474 Phase 1: the XSS-scanner (Dalfox) probe signal fold. A Dalfox marker yields a telemetry
 * Detection tagged `scanner.xss-probe` without changing a served byte (signal-only, like WaymapProbe).
 * Markers per docs/research/scanner-confirmation-and-ai-agent-deception.md. The bare `90197752`, a
 * bare `dalfox` mention, and the "≥15 special chars" heuristic are deliberately NOT matched (FP-safe).
 */
final class XssProbeSignalTest extends TestCase
{
    private function engine(): Honeypot
    {
        return new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php'),
            new Config('detect', null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, false)
        );
    }

    /** @return array<string,array{0:string,1:string,2:array<string,string>}> */
    public function dalfoxMarkers(): array
    {
        return [
            'sentinel'   => ['/', 'q=dlfx_sentinel_q_8a3f', []],
            'dlxmid'     => ['/', 'p=dlxmid12ab', []],
            'dlx-nonce'  => ['/search', 'q="><svg onload=alert(1) class=dlx1a2b3c4d>', []],
            'xld-nonce'  => ['/', 'x=xld0f1e2d3a', []],
            'dalfox-id'  => ['/', 'q=<img src=x id=dalfox>', []],
            'dalfox-ua'  => ['/', '', ['User-Agent' => 'Mozilla/5.0 .dalfox']],
        ];
    }

    /** @dataProvider dalfoxMarkers */
    public function test_dalfox_marker_folds_xss_probe_tag(string $path, string $query, array $headers): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', $path, $query, $headers), SiteProfile::empty());
        self::assertTrue($verdict->detection->matched, 'a Dalfox marker must fold a signal match');
        self::assertContains('scanner.xss-probe', $verdict->detection->tags());
        self::assertSame('info', $verdict->severity);
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle, 'signal-only: nothing served/faked');
    }

    /** @return array<string,array{0:string,1:string,2:array<string,string>}> */
    public function benignNegatives(): array
    {
        return [
            'bare-number'       => ['/', 'id=90197752', []],                    // dropped marker — benign numeric id
            'dense-punct-json'  => ['/api', 'f=' . rawurlencode('{"a":["and","or"],"s":"/\\\'{<>\"(;=|}[]"}'), []], // >=15 specials, no marker
            'dalfox-mention'    => ['/', 'q=we tested with dalfox and burp suite', []],  // bare tool name, no marker ctx
            'dlx-too-short'     => ['/', 'q=dlxab', []],                          // dlx + <4 hex
            'prototype-word'    => ['/', 'kind=prototype', []],
            'middleware'        => ['/', 'layer=middleware redux', []],
        ];
    }

    /** @dataProvider benignNegatives */
    public function test_benign_values_do_not_fold_the_xss_probe_tag(string $path, string $query, array $headers): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', $path, $query, $headers), SiteProfile::empty());
        self::assertNotContains('scanner.xss-probe', $verdict->detection->tags(), "benign must not tag: {$query}");
    }

    public function test_probe_unit_matches_markers_rejects_benign(): void
    {
        self::assertTrue(XssProbe::detect(new RequestContext('GET', '/', 'q=dlfx_sentinel_q_1a2b')));
        self::assertTrue(XssProbe::detect(new RequestContext('GET', '/', 'q=dlx1a2b3c4d')));
        self::assertFalse(XssProbe::detect(new RequestContext('GET', '/', 'id=90197752')));
        self::assertFalse(XssProbe::detect(new RequestContext('GET', '/', 'q=dalfox review notes')));
    }

    public function test_served_response_byte_identical_on_a_real_route(): void
    {
        // A Dalfox UA marker must not change a served route's bytes (anti-differential).
        $hp = new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php'),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
        $probe = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', '', ['User-Agent' => '.dalfox'], null, 'x.test'));
        $benign = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', '', ['User-Agent' => 'curl/8.0'], null, 'x.test'));
        self::assertNotNull($probe);
        self::assertNotNull($benign);
        self::assertSame($benign->status, $probe->status);
        self::assertSame($benign->body, $probe->body, 'Dalfox marker must not alter a served byte');
    }
}
