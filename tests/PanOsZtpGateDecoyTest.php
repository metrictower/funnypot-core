<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0460: Palo Alto PAN-OS management auth-bypass decoy (CVE-2025-0108, CISA KEV). Enrich of the corpus
 * ztp_gate bundle (pid pan-os) at the path-confusion probe path, route_key-guarded so only that path gets
 * the dressed PAN-OS "Zero Touch Provisioning" page. Inert, static; the co-tenant .js.map key is untouched.
 */
final class PanOsZtpGateDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private const ZTP_PATH = '/unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css';

    private function engine(string $ceiling = 'critical'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, $ceiling, 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function get(string $path, string $ceiling = 'critical'): ?\Funnypot\Core\SynthesizedResponse
    {
        return $this->engine($ceiling)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    public function test_ztp_probe_serves_the_panos_management_page(): void
    {
        $r = $this->get(self::ZTP_PATH);
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        // Nettacker/nuclei confirmation: status 200 + Content-Type text/html + body `Zero Touch Provisioning`.
        self::assertStringContainsString('text/html', (string) ($r->headers['Content-Type'] ?? ''));
        $b = (string) $r->body;
        self::assertStringContainsString('<title>Zero Touch Provisioning', $b, 'corpus bundle body-word witness');
        self::assertStringContainsString('PAN-OS', $b, 'coherent PAN-OS chrome');
    }

    public function test_content_type_is_html_despite_css_suffix(): void
    {
        // The URL ends in .css but the authentic executed-PHP response is text/html (the exploit's tell).
        $r = $this->get(self::ZTP_PATH);
        self::assertNotNull($r);
        self::assertStringStartsWith('text/html', (string) ($r->headers['Content-Type'] ?? ''));
    }

    public function test_cotenant_js_map_is_not_dressed_with_the_full_page(): void
    {
        // The route_key guard pins only the x.css path; the co-tenant /php/ztp_gate.php/.js.map (same pid)
        // keeps its minimal corpus stub — it must NOT carry the enriched management chrome.
        $r = $this->get('/php/ztp_gate.php/.js.map');
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringNotContainsString('Awaiting configuration', $b, 'co-tenant must not get the enriched body');
    }

    public function test_no_request_byte_reflected(): void
    {
        // Static canned HTML — a marker in the (ignored) query must never appear in the body.
        $r = $this->engine()->respond(new RequestContext('GET', self::ZTP_PATH, 'x=Zpanossentinel88Z', [], null, 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('Zero Touch Provisioning', $b);
        self::assertStringNotContainsString('Zpanossentinel88Z', $b);
    }

    // --- FP-0564: one coherent PAN-OS identity (ztp-gate reads {{persona.panos.version}}) ---------

    private function ztpVersion(string $deploySeed, string $requestSeed = 'req'): string
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config(
            mode: 'respond',
            gate: static function (RequestContext $r): bool { return true; },
            personaSeed: static function (RequestContext $r) use ($requestSeed): string { return $requestSeed; },
            severityCeiling: 'critical',
            attackEmulation: true,
            deploySeed: $deploySeed,
        );
        $hp = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
        $b = (string) ($hp->respond(new RequestContext('GET', self::ZTP_PATH, '', [], null, 'x.test'))->body ?? '');
        self::assertSame(1, preg_match('/PAN-OS (\S+)</', $b, $m), "ztp-gate must advertise a PAN-OS version: {$b}");

        return $m[1];
    }

    public function test_ztp_version_is_persona_derived_and_cve_2025_0108_affected(): void
    {
        // Every entry in PANOS_BUILDS is on the affected side of CVE-2025-0108 (the ztp-gate's own CVE), so
        // the one shared persona version is always a believable unpatched target for this exact decoy.
        $affected = ['10.1.0', '10.2.0', '11.0.0', '11.1.0'];
        $seen = [];
        for ($s = 0; $s < 60; $s++) {
            $v = $this->ztpVersion('box' . $s);
            self::assertContains($v, $affected, "deploy {$s}: ztp version {$v} must be CVE-2025-0108-affected");
            $seen[$v] = true;
        }
        self::assertGreaterThan(1, count($seen), 'the version must vary across deploys (not a fleet constant)');
    }

    public function test_ztp_version_is_deploy_stable_not_per_source(): void
    {
        // The pre-FP-0564 ztp-gate picked per-source-IP (per request); the persona version is deploy-stable,
        // so two different request seeds on ONE deploy now see the SAME version (the coherence this closes).
        self::assertSame($this->ztpVersion('box-X', 'req-A'), $this->ztpVersion('box-X', 'req-B'),
            'ztp version must be stable across requests within a deploy');
        // ...and it is deterministic per deploy.
        self::assertSame($this->ztpVersion('box-Y'), $this->ztpVersion('box-Y'));
    }
}
