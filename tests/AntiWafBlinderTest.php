<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0425: the anti-WAF blinder, exercised end-to-end through Honeypot::respond(). sqlmap's fixed
 * WAF-check polyglot must be served the route's OWN baseline (never the 1064/error a plain union would
 * draw), so sqlmap's checkWaf ratio stays >=0.5 and it keeps scanning in default mode; a REAL SQLi still
 * fires its decoy (no blinding of genuine attacks); and the recon is surfaced to the observer as a
 * signal-only telemetry tag.
 */
final class AntiWafBlinderTest extends TestCase
{
    private const POLY = 'AND 1=1 UNION ALL SELECT 1,NULL,\'<script>alert("XSS")</script>\',table_name'
        . ' FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell(\'cat ../../../etc/passwd\')#';

    /** A generic extraction a real attacker sends — union + information_schema, but NOT the polyglot. */
    private const GENERIC = '1 UNION ALL SELECT table_name,2 FROM information_schema.tables';

    /** @var array<string,mixed>|null */
    private static $idx = null;

    private function engine(?Observer $observer = null): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, 'fixed');
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg, $observer);
    }

    private function respond(string $path, string $query, ?Observer $observer = null): ?SynthesizedResponse
    {
        return $this->engine($observer)->respond(new RequestContext('GET', $path, $query, [], null, 'x.test'));
    }

    /** SequenceMatcher.quick_ratio equivalent (sqlmap's checkWaf metric): 2*Σmin / (len_a+len_b). */
    private function quickRatio(string $a, string $b): float
    {
        $ca = count_chars($a, 1);
        $cb = count_chars($b, 1);
        $m = 0;
        foreach ($ca as $k => $v) {
            if (isset($cb[$k])) {
                $m += min($v, $cb[$k]);
            }
        }
        $t = strlen($a) + strlen($b);

        return $t > 0 ? 2 * $m / $t : 1.0;
    }

    // --- store-MISS path (/products.php): unmarked id=1 -> plain 404 (null); a generic union draws an
    //     attack serve (200); the polyglot is blinded back to the SAME 404 the unmarked request gets.

    public function test_generic_sqli_still_fires_on_a_store_miss(): void
    {
        // No-regression: the honeypot is NOT blinded for a real attacker — the generic union is served an
        // attack response, materially different from the unmarked 404 baseline.
        $baseline = $this->respond('/products.php', 'id=1');
        self::assertNull($baseline, 'the unmarked baseline on this store-miss path is a plain 404');
        $generic = $this->respond('/products.php', 'id=' . rawurlencode(self::GENERIC));
        self::assertNotNull($generic, 'a genuine union/information_schema SQLi must still be served (not blinded)');
        self::assertSame(200, $generic->status);
    }

    public function test_waf_check_polyglot_is_blinded_on_a_store_miss(): void
    {
        // The polyglot resolves to the SAME plain 404 (null) the unmarked request gets — NOT the attack
        // serve the generic union draws — so sqlmap sees baseline-identical bytes (ratio 1.0) and stays
        // blinded. This is the exact divergence (served vs 404) the blinder removes for the fixed polyglot.
        $baseline = $this->respond('/products.php', 'id=1');
        $poly = $this->respond('/products.php', 'id=' . rawurlencode(self::POLY));
        self::assertNull($baseline, 'unmarked baseline is a 404');
        self::assertNull($poly, 'the WAF-check polyglot must be blinded to the same 404 (no attack serve)');
    }

    // --- param-route (differential) path: the polyglot self-resolves to baseline P (NOT suppressed).

    public function test_waf_check_polyglot_serves_baseline_on_the_differential_route(): void
    {
        $baseline = $this->respond('/catalog/electronics', 'id=1');
        self::assertNotNull($baseline);
        self::assertSame(200, $baseline->status);
        self::assertStringContainsString('Product catalog', $baseline->body);

        $poly = $this->respond('/catalog/electronics', 'id=' . rawurlencode(self::POLY));
        self::assertNotNull($poly);
        self::assertSame(200, $poly->status, 'the polyglot on the differential route is a 200, not an error');
        self::assertStringContainsString('Product catalog', $poly->body, 'it serves the catalog baseline, not a 1064');
        self::assertStringNotContainsString('SQL syntax', $poly->body, 'never the DB error page');

        $ratio = $this->quickRatio($poly->body, $baseline->body);
        self::assertGreaterThanOrEqual(0.7, $ratio, 'polyglot vs baseline similarity must clear sqlmap AC (>=0.7)');
        self::assertFalse($ratio < 0.5, "sqlmap checkWaf retVal == (ratio < 0.5) must be False (ratio={$ratio})");
    }

    // --- real SQLi on the differential route is still differentiated (no-regression).

    public function test_generic_false_sqli_still_differentiates_on_the_route(): void
    {
        $baseline = $this->respond('/catalog/electronics', 'id=1');
        $false = $this->respond('/catalog/electronics', 'id=' . rawurlencode('1 AND 1=2'));
        self::assertNotNull($false);
        self::assertSame(200, $false->status);
        self::assertNotSame($baseline->body, $false->body, 'a real FALSE probe still yields the differential empty page');
    }

    // --- heuristic alphabet: response unchanged; telemetry only.

    public function test_heuristic_alphabet_leaves_the_response_unchanged(): void
    {
        $baseline = $this->respond('/catalog/electronics', 'id=1');
        $heur = $this->respond('/catalog/electronics', 'id=' . rawurlencode('\'"()(),.()'));
        self::assertNotNull($heur);
        self::assertSame($baseline->body, $heur->body, 'the heuristic-alphabet probe must serve the unchanged baseline');
    }

    // --- telemetry: the recon reaches the observer even when respond() serves nothing (store-miss 404).

    public function test_waf_check_tag_reaches_the_observer_on_a_store_miss(): void
    {
        $obs = new CapturingObserver();
        $this->respond('/products.php', 'id=' . rawurlencode(self::POLY), $obs);
        self::assertTrue($obs->sawTag('tool.sqlmap.wafcheck'), 'the WAF-check telemetry tag must reach onDetection');
    }

    public function test_heuristic_tag_reaches_the_observer(): void
    {
        $obs = new CapturingObserver();
        $this->respond('/products.php', 'id=' . rawurlencode('\'"()(),.()'), $obs);
        self::assertTrue($obs->sawTag('tool.sqlmap.heuristic'), 'the heuristic-alphabet telemetry tag must reach onDetection');
    }
}

/** Captures the tags of every Detection passed to onDetection. */
final class CapturingObserver implements Observer
{
    /** @var string[] */
    public $tags = [];

    public function onDetection(RequestContext $r, Detection $detection): void
    {
        foreach ($detection->matches as $m) {
            foreach ($m->tags as $t) {
                $this->tags[] = $t;
            }
        }
    }

    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
    }

    public function sawTag(string $tag): bool
    {
        return in_array($tag, $this->tags, true);
    }
}
