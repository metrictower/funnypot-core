<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0555: D-Link HNAP SOAPAction-header command-injection RCE decoy (attack-hnap-soapaction-rce,
 * CVE-2015-2051). RouterSploit's dlink/multi_hnap_rce exploit phase POSTs /HNAP1/ with the shell
 * command injected in the SOAPAction HEADER and is BLIND (reads no response), so the decoy returns a
 * plausible canned GetDeviceSettings SOAP envelope (200) with the injected command NEVER reflected.
 * The paired check() (GET /HNAP1/ -> 200 + "D-Link" + "SOAPActions") is served by 57; the login oracle
 * (96, POST + <Action> body) must not be shadowed.
 */
final class HnapSoapActionRceTest extends TestCase
{
    /** A unique token injected as the "command" — must never appear in the served response. */
    private const CANARY = 'rce_canary_zzt';

    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true,
            personaSeed: static fn (RequestContext $r): string => 'fixed',
            attackEmulation: true,
            deploySeed: 'fixed'
        );

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    /** @param array<string,string> $headers */
    private function serve(string $method, array $headers, ?string $body): ?object
    {
        return $this->engine()->respond(new RequestContext($method, '/HNAP1/', '', $headers, $body, 'x.test'));
    }

    public function test_rce_post_serves_canned_envelope_and_never_reflects_the_injected_command(): void
    {
        $soapAction = 'http://purenetworks.com/HNAP1/GetDeviceSettings/`echo ' . self::CANARY . '`';
        $r = $this->serve('POST', ['SOAPAction' => $soapAction], null);

        self::assertNotNull($r, 'the RCE POST must be served a decoy, not a 404');
        self::assertSame(200, $r->status);
        $ct = $r->headers['Content-Type'] ?? $r->headers['content-type'] ?? '';
        self::assertSame('text/xml; charset=utf-8', $ct, 'Content-Type matches a SOAP request');
        self::assertStringContainsString('<ModelName>DIR-850L</ModelName>', $r->body, 'canned D-Link envelope');
        self::assertStringContainsString('SOAPActions', $r->body);
        // Load-bearing safety assertion: the injected command is NEVER reflected (inert, no echo).
        self::assertStringNotContainsString(self::CANARY, $r->body, 'the injected command must not be reflected');
    }

    public function test_rce_match_is_action_name_agnostic(): void
    {
        // The vuln is not specific to GetDeviceSettings; any HNAP action with a trailing injection hits.
        $soapAction = 'http://purenetworks.com/HNAP1/GetFirmwareStatus/`id`';
        $r = $this->serve('POST', ['SOAPAction' => $soapAction], null);
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('SOAPActions', $r->body);
    }

    public function test_check_phase_get_recon_still_served(): void
    {
        // RouterSploit check() is a GET keyed on 200 + "D-Link" + "SOAPActions" — served by 57; regress-guard.
        $r = $this->serve('GET', [], null);
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('D-Link', $r->body);
        self::assertStringContainsString('SOAPActions', $r->body);
    }

    public function test_benign_login_post_still_reaches_the_login_oracle(): void
    {
        // A clean login POST (no header injection) must NOT be shadowed by the RCE rule → 96 serves FAILED.
        $r = $this->serve('POST', ['SOAPAction' => 'http://purenetworks.com/HNAP1/Login'], '<Action>login</Action>');
        self::assertNotNull($r);
        self::assertStringContainsString('LoginResponse', $r->body);
        self::assertStringContainsString('FAILED', $r->body);
        self::assertStringNotContainsString('DIR-850L', $r->body, 'a benign login must not get the RCE envelope');
    }

    public function test_benign_soapaction_without_metachar_does_not_match_the_rce_rule(): void
    {
        // Tightness: a SOAPAction ending at the action name (no trailing /<...> and no shell metachar)
        // is benign; with no <Action> body it matches neither the RCE rule nor the login oracle → 404.
        $r = $this->serve('POST', ['SOAPAction' => 'http://purenetworks.com/HNAP1/GetDeviceSettings'], null);
        self::assertNull($r, 'a benign metachar-free POST must not trigger the RCE decoy');
    }
}
