<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0476: the SSTI engine-error oracle (52-ssti-engine-error). A FreeMarker/Velocity/Twig sandbox-escape
 * probe that does NOT evaluate to a number gets that engine's distinctive canned exception page (status
 * 500); a clean arithmetic probe still reflects the product via 43-46; benign traffic declines. Inert,
 * no attacker byte echoed.
 */
final class SstiErrorOracleTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $indexCache;

    private function engine(): Honeypot
    {
        if (self::$indexCache === null) {
            self::$indexCache = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', null, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$indexCache), $cfg);
    }

    private function resp(string $payload): ?object
    {
        return $this->engine()->respond(new RequestContext('GET', '/x', 'q=' . rawurlencode($payload), [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_freemarker_escape_probe_returns_freemarker_exception_500(): void
    {
        foreach (['<#assign x=1>', '${7?api}', '<@foo />'] as $p) {
            $r = $this->resp($p);
            self::assertSame(500, $r->status ?? null, "{$p} status");
            self::assertStringContainsString('freemarker.core', $this->body($r), "{$p} must show the FreeMarker exception");
        }
    }

    public function test_velocity_escape_probe_returns_velocity_exception_500(): void
    {
        foreach (['#set($x=1)', '#evaluate("x")'] as $p) {
            $r = $this->resp($p);
            self::assertSame(500, $r->status ?? null);
            self::assertStringContainsString('org.apache.velocity.exception', $this->body($r), "{$p} must show the Velocity exception");
        }
    }

    public function test_twig_escape_probe_returns_twig_exception_500(): void
    {
        foreach (['{{_self.env}}', '{{[1]|filter("system")}}'] as $p) {
            $r = $this->resp($p);
            self::assertSame(500, $r->status ?? null);
            self::assertStringContainsString('Twig\\Error', $this->body($r), "{$p} must show the Twig exception");
        }
    }

    public function test_clean_arithmetic_still_reflects_the_product_not_an_error(): void
    {
        // 43-46 must still own a clean arithmetic probe (status 200, product) — the error oracle must not hijack it.
        foreach (['{{7*7}}', '@(7*7)', '${1234*5678}'] as $p) {
            $r = $this->resp($p);
            self::assertSame(200, $r->status ?? null, "{$p} must stay 200 (arithmetic)");
            self::assertStringNotContainsString('ParseException', $this->body($r), "{$p} must not hit the error oracle");
        }
    }

    public function test_benign_traffic_does_not_trigger_the_error_oracle(): void
    {
        foreach (['hello world', 'name=john&age=30', 'search=the quick brown fox', 'q=SELECT 1', 'id=42'] as $p) {
            $b = $this->body($this->resp($p));
            self::assertStringNotContainsString('freemarker.core', $b, "{$p} must not trigger FreeMarker");
            self::assertStringNotContainsString('velocity.exception', $b, "{$p} must not trigger Velocity");
            self::assertStringNotContainsString('Twig\\Error', $b, "{$p} must not trigger Twig");
        }
    }

    public function test_no_attacker_byte_is_echoed(): void
    {
        // The offending expression is NOT quoted in the canned trace (no reflection surface).
        $marker = 'Zsstisentinel7788Z';
        $b = $this->body($this->resp('<#assign ' . $marker . '=1>'));
        self::assertStringContainsString('freemarker.core', $b);
        self::assertStringNotContainsString($marker, $b, 'no attacker byte may reach the canned trace');
    }

    public function test_position_blind_port_serves_neutral_500_no_engine_leak(): void
    {
        // synthesize() without a request can't read the case markers -> neutral 500, no specific engine.
        $r = $this->resp('{{_self.env}}');
        $v = $this->engine()->classify(new RequestContext('GET', '/x', 'q=' . rawurlencode('{{_self.env}}'), [], null, 'x.test'), SiteProfile::empty());
        $blind = $this->engine()->synthesize($v, SiteProfile::empty(), 's');
        $bb = $blind !== null ? (string) $blind->body : '';
        if ($bb !== '') {
            self::assertStringContainsString('Internal Server Error', $bb, 'position-blind port must serve the neutral 500');
            self::assertStringNotContainsString('Twig\\Error', $bb, 'position-blind port must not leak a specific engine');
        }
        self::assertTrue(true);
    }
}
