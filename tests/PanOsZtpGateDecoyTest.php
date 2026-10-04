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
}
