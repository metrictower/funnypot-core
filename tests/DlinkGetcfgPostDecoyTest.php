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
 * FP-0556: the D-Link getcfg.php DEVICE.ACCOUNT credential disclosure must answer on POST (the real
 * exploit + RouterSploit dlink/dir_645_password_disclosure POST SERVICES=DEVICE.ACCOUNT), not only GET.
 * 426-dlink-getcfg-post dresses the POST /getcfg.php bundle (pid cve2024). Inert; admin + seeded password.
 */
final class DlinkGetcfgPostDecoyTest extends TestCase
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

    private function getcfg(string $method): ?\Funnypot\Core\SynthesizedResponse
    {
        return $this->engine()->respond(new RequestContext($method, '/getcfg.php', '',
            ['Content-Type' => 'application/x-www-form-urlencoded'], 'SERVICES=DEVICE.ACCOUNT', 'x.test'));
    }

    public function test_post_getcfg_discloses_credentials(): void
    {
        $r = $this->getcfg('POST');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('text/xml', (string) ($r->headers['Content-Type'] ?? ''));
        $b = (string) $r->body;
        self::assertStringContainsString('<name>admin</name>', $b, 'RouterSploit dir_645_password_disclosure witness');
        self::assertStringContainsString('<password>', $b);
    }

    public function test_get_getcfg_still_discloses_credentials(): void
    {
        // The pre-existing GET enrich (364-dlink-getcfg) must stay intact.
        $b = (string) ($this->getcfg('GET')->body ?? '');
        self::assertStringContainsString('<name>admin</name>', $b);
        self::assertStringContainsString('<password>', $b);
    }

    public function test_no_request_byte_reflected(): void
    {
        $r = $this->engine()->respond(new RequestContext('POST', '/getcfg.php', '',
            ['Content-Type' => 'application/x-www-form-urlencoded'], 'SERVICES=DEVICE.ACCOUNT&x=Zgetcfgsentinel33Z', 'x.test'));
        $b = $r !== null ? (string) $r->body : '';
        self::assertStringContainsString('<name>admin</name>', $b);
        self::assertStringNotContainsString('Zgetcfgsentinel33Z', $b);
    }
}
