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
use PHPUnit\Framework\TestCase;

/**
 * FP-0415 Phase 1: the Waymap scanner-fingerprint signal fold. A Waymap v8 probe token yields a
 * telemetry Detection tagged `scanner.fingerprint.waymap` (attribution), WITHOUT changing a single
 * served byte — the baseline response is byte-identical to a benign request's (no differential tell,
 * security invariant #1). Mirrors OastSeamTest's signal-only-fold assertions.
 */
final class WaymapFingerprintTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function engine(string $mode = 'detect'): Honeypot
    {
        return new Honeypot($this->store(), new Config(
            $mode, null, 'matched-only', null, 'coherent', Style::MINIMAL, 'high', 65536, 0, 0, false
        ));
    }

    /** @return array<string,array{0:string,1:string,2:array<string,string>}> method/query/headers per token */
    public function waymapTokens(): array
    {
        return [
            'cmdi'       => ['/search', 'p=WAYMAP_CMDI_deadbeef', []],
            'xss'        => ['/search', 'q=wymapxss12ab34', []],
            'proto-poll' => ['/api/item', '__proto__[waymap]=polluted', []],
            'recon'      => ['/', 'id=waymap_recon_deadbeef', []],
            'lfi-prefix' => ['/', 'f=waymap_lfi_x', []],
            'cors'       => ['/', 'o=waymap_cors_y', []],
            'crlf'       => ['/login', 'redirect=%0D%0AHeader-Test:trixsec', []],
            'lfi-rce-ua' => ['/', '', ['User-Agent' => 'WAYMAP_LFI_RCE']],
        ];
    }

    /** @dataProvider waymapTokens */
    public function test_waymap_token_folds_a_scanner_fingerprint_tag(string $path, string $query, array $headers): void
    {
        $r = new RequestContext('GET', $path, $query, $headers);
        $verdict = $this->engine()->classify($r, SiteProfile::empty());

        self::assertTrue($verdict->detection->matched, 'a Waymap token must fold a signal match');
        self::assertContains('scanner.fingerprint.waymap', $verdict->detection->tags(), 'the AC telemetry event tag');
        self::assertContains('waymap', $verdict->detection->tags());
        self::assertSame('info', $verdict->severity, 'attribution severity, not a served-decoy tier');
        // A pure Waymap-only hit on a store-miss (null handle) is bumped CLEAN -> SCANNER_PROBE.
        self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification);
        self::assertNull($verdict->fakeHandle, 'signal-only: nothing is served/faked');
    }

    /**
     * Byte-identity: the served response to a Waymap-token request is identical to a benign request's
     * on the same path — the fold enriches telemetry only, never the served bytes.
     */
    public function test_served_response_is_byte_identical_to_the_benign_baseline(): void
    {
        $hp = $this->engine('respond');
        foreach ($this->waymapTokens() as $label => [$path, $query, $headers]) {
            $probe = $hp->respond(new RequestContext('GET', $path, $query, $headers));
            $benign = $hp->respond(new RequestContext('GET', $path, '', []));
            $ps = $probe === null ? 'NULL' : ($probe->status . '|' . $probe->body);
            $bs = $benign === null ? 'NULL' : ($benign->status . '|' . $benign->body);
            self::assertSame($bs, $ps, "Waymap probe [{$label}] must serve the benign baseline byte-for-byte");
        }
    }

    /** @return array<string,array{0:string,1:string,2:array<string,string>}> */
    public function benignNegatives(): array
    {
        return [
            'prototype-word'   => ['/', 'kind=prototype', []],
            'reconnaissance'   => ['/', 'q=reconnaissance report', []],
            'trixsec-no-crlf'  => ['/', 'author=trixsec', []],       // handle mention, NOT the CRLF probe
            'max-forwards'     => ['/', '', ['Max-Forwards' => '10']],
            'bare-waymap'      => ['/', 'q=waymap scanner wiki', []], // no marker token
            'xss-word'         => ['/', 'q=xss cheat sheet', []],
        ];
    }

    /** @dataProvider benignNegatives */
    public function test_benign_values_do_not_fold_the_waymap_tag(string $path, string $query, array $headers): void
    {
        $verdict = $this->engine()->classify(new RequestContext('GET', $path, $query, $headers), SiteProfile::empty());
        self::assertNotContains('scanner.fingerprint.waymap', $verdict->detection->tags(), "benign must not tag: {$query}");
    }
}
