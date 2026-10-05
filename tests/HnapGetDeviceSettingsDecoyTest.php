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
 * FP-0441 (AC1): D-Link HNAP GetDeviceSettings recon decoy. GET /HNAP1/ returns the device-settings SOAP
 * envelope so RouterSploit's dlink/multi_hnap check (200 + "D-Link" + "SOAPActions") succeeds. GET-only, so
 * the POST-only HNAP login oracle (96-hnap-login) is untouched. Inert, static.
 */
final class HnapGetDeviceSettingsDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    public function test_get_hnap1_returns_device_settings(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/HNAP1/', '',
            ['SOAPAction' => '"http://purenetworks.com/HNAP1/GetDeviceSettings"'], null, 'x.test'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('text/xml', (string) ($r->headers['Content-Type'] ?? ''));
        $b = (string) $r->body;
        // RouterSploit dlink/multi_hnap check: 200 + "D-Link" + "SOAPActions" in body.
        self::assertStringContainsString('D-Link', $b);
        self::assertStringContainsString('SOAPActions', $b);
        self::assertStringContainsString('<ModelName>DIR-850L</ModelName>', $b);
    }

    public function test_post_hnap1_login_oracle_still_wins(): void
    {
        // The GET recon rule must not shadow the POST-only HNAP login oracle (96-hnap-login).
        $r = $this->engine()->respond(new RequestContext('POST', '/HNAP1/', '',
            ['Content-Type' => 'text/xml'], '<Action>request</Action>', 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('Challenge', $b, 'POST login challenge (96-hnap-login) intact');
        self::assertStringNotContainsString('<ModelName>DIR-850L</ModelName>', $b, 'POST must not get the GET recon body');
    }

    public function test_no_request_byte_reflected(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/HNAP1/', 'x=Zhnapsentinel44Z',
            ['SOAPAction' => '"http://purenetworks.com/HNAP1/GetDeviceSettings/Zhnapsentinel44Z"'], null, 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('DIR-850L', $b);
        self::assertStringNotContainsString('Zhnapsentinel44Z', $b);
    }
}
