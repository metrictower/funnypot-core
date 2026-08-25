<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Crs;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The response-precedence guarantee, proven end to end.
 *
 * Honeypot::respond() routes a request to the nuclei corpus / route decoys FIRST (tier 1,
 * a byte-exact response derived from what the scanner probes for). Only a request that
 * resolves to NO route falls through to tryAttack() → TemplateAttackEmulator (tier 2), where
 * CRS-broadened generic attack-class emulation lives. So a request that matches BOTH a nuclei
 * template AND a CRS attack class must serve the nuclei-exact response, never the CRS-generic
 * one — nuclei-exact always beats CRS-generic.
 */
final class CrsPrecedenceTest extends TestCase
{
    private function honeypot(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../../resources/compiled/nuclei-index.php');

        return new Honeypot($store, new Config(
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
            true                                                         // attackEmulation
        ));
    }

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(__DIR__ . '/../../resources/compiled/funnypot-attack.php');
    }

    /**
     * A CRS-only SQLi pattern (942140 "sqlite_master") that funnypot's own hand-authored
     * 50-sqli rule does not cover — so a match here is unambiguously the CRS-broadened class.
     */
    private const CRS_ONLY_SQLI = 'conf=1;select * from sqlite_master';

    public function test_crs_class_matches_this_request_in_the_emulator(): void
    {
        // Baseline for the precedence claim: the CRS attack class genuinely fires on this
        // request when the emulator is consulted directly (tier 2 in isolation).
        $attack = $this->emulator()->emulate(new RequestContext('GET', '/webpack.config.js', self::CRS_ONLY_SQLI));

        self::assertNotNull($attack);
        self::assertSame('attack-crs-sqli', $attack->satisfies->templateIds()[0]);
        self::assertStringContainsString('SQL syntax', $attack->body);
    }

    public function test_nuclei_route_beats_the_crs_class_on_a_routed_path(): void
    {
        // Same request through the full engine: /webpack.config.js IS a compiled nuclei route,
        // so tier 1 wins and tryAttack() is never reached.
        $resp = $this->honeypot()->respond(new RequestContext('GET', '/webpack.config.js', self::CRS_ONLY_SQLI));

        self::assertNotNull($resp);
        self::assertStringContainsString('module.exports', $resp->body);   // the nuclei-exact webpack response
        self::assertStringNotContainsString('SQL syntax', $resp->body);     // NOT the CRS-generic SQL error
    }

    public function test_crs_class_serves_only_when_no_nuclei_route_wins(): void
    {
        // The complement: on a path with no compiled route, tier 1 misses and the CRS-broadened
        // class is served from tier 2 — confirming CRS is reachable, just always second.
        $resp = $this->honeypot()->respond(new RequestContext('GET', '/no/such/route', self::CRS_ONLY_SQLI));

        self::assertNotNull($resp);
        self::assertStringContainsString('SQL syntax', $resp->body);
    }
}
