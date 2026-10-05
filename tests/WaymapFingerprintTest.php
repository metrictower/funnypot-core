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

    /** A respond engine over the FULL compiled index, so real routes actually serve a body. */
    private function fullEngine(): Honeypot
    {
        return new Honeypot(
            new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php'),
            new Config(
                'respond',
                static fn (RequestContext $r): bool => true,
                'matched-only',
                static fn (RequestContext $r): string => 'fixed',
                'coherent',
                Style::REALISTIC,
                'critical',
                65536, 0, 0, false, null, null, null, 'fixed'
            )
        );
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
     * Anti-differential invariant (structural): folding a Waymap match must not inject a servable
     * handle. Asserts the fakeHandle is IDENTICAL with and without the token — a fold that changed the
     * served path would flip null<->handle here. (The 8 store-miss fixtures are all null-handle, so
     * this proves the fold stays null; the served-body case below proves identity on a path that
     * actually serves.)
     */
    public function test_fold_does_not_inject_a_servable_handle(): void
    {
        foreach ($this->waymapTokens() as $label => [$path, $query, $headers]) {
            $probe = $this->engine()->classify(new RequestContext('GET', $path, $query, $headers), SiteProfile::empty());
            $benign = $this->engine()->classify(new RequestContext('GET', $path, '', []), SiteProfile::empty());
            self::assertSame($benign->fakeHandle, $probe->fakeHandle, "fold must not inject a handle: {$label}");
        }
    }

    /**
     * Byte-identity on a path that ACTUALLY serves: the User-Agent Waymap token must not change a
     * single served byte of a real route response (the load-bearing anti-differential assert). Carries
     * the token in the UA so the served route (/.ssh/id_rsa canary) is reached identically either way.
     */
    public function test_waymap_ua_token_serves_route_byte_identical(): void
    {
        $hp = $this->fullEngine();
        $probe = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', '', ['User-Agent' => 'WAYMAP_LFI_RCE'], null, 'x.test'));
        $benign = $hp->respond(new RequestContext('GET', '/.ssh/id_rsa', '', ['User-Agent' => 'curl/8.0'], null, 'x.test'));

        self::assertNotNull($probe, 'the route must actually serve (else the test is vacuous)');
        self::assertNotNull($benign);
        self::assertSame($benign->status, $probe->status);
        self::assertSame($benign->body, $probe->body, 'the Waymap UA token must not alter a served byte');
        // Headers identical EXCEPT X-Request-Id, which is a per-request random nonce (an anti-
        // fingerprint feature that differs between ANY two requests, benign or not — not a Waymap
        // differential). Compare with it stripped.
        $strip = static function (array $h): array {
            unset($h['X-Request-Id']);
            return $h;
        };
        self::assertSame($strip($benign->headers), $strip($probe->headers), 'no Waymap-induced header differential');
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
