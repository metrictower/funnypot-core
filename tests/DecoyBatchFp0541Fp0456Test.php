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
 * FP-0541: FortiOS /remote/fgt_lang served as application/javascript (CT fix for wapiti's mod_forti label
 * + invariant 5), witness preserved. FP-0456 core slice: the Citrix Bleed leak carries a format-correct
 * labelled NSC_AAAC=<64 hex> session cookie (what a Bleed harvester greps for).
 */
final class DecoyBatchFp0541Fp0456Test extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function body(string $method, string $path, string $query = '', array $headers = []): string
    {
        $r = $this->engine()->respond(new RequestContext($method, $path, $query, $headers, null, 'x.test'));

        return $r !== null ? (string) $r->body : '';
    }

    private function contentType(string $path): string
    {
        $r = $this->engine()->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));

        return $r !== null ? (string) ($r->headers['Content-Type'] ?? '') : '';
    }

    // ---- FP-0541 FortiOS fgt_lang ----

    public function test_fgt_lang_served_as_javascript(): void
    {
        self::assertStringContainsString('javascript', $this->contentType('/remote/fgt_lang'),
            'wapiti mod_forti requires a javascript Content-Type (was text/plain)');
    }

    public function test_fgt_lang_keeps_the_witness(): void
    {
        self::assertStringContainsString('var fgt_lang =', $this->body('GET', '/remote/fgt_lang'));
    }

    public function test_fgt_lang_enrich_does_not_touch_the_login_routes(): void
    {
        // route_key guards /remote/fgt_lang only — the FortiOS SSL-VPN login routes keep their own bodies.
        self::assertStringNotContainsString('var fgt_lang =', $this->body('GET', '/remote/login'));
    }

    // ---- FP-0456 Citrix Bleed NSC_AAAC canary ----

    public function test_citrix_bleed_leaks_labelled_nsc_aaac_cookie(): void
    {
        $b = $this->body('GET', '/oauth/idp/.well-known/openid-configuration', '', ['Host' => str_repeat('a', 300)]);
        self::assertStringContainsString('authorization_endpoint', $b, 'the OIDC leak still confirms');
        self::assertSame(1, preg_match('/NSC_AAAC=[0-9a-f]{64}; Path=\/; Secure; HttpOnly/', $b),
            'leak carries a format-correct labelled NSC_AAAC=<64 lowercase hex> session cookie');
    }

    public function test_citrix_bleed_reflects_no_request_byte(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/oauth/idp/.well-known/openid-configuration',
            'x=Zcitrixsentinel77Z', ['Host' => 'Zcitrixsentinel77Z'], null, 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('NSC_AAAC=', $b);
        self::assertStringNotContainsString('Zcitrixsentinel77Z', $b);
    }
}
