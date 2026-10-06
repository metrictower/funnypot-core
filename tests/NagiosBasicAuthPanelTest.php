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
 * FP-0391: a never-validating HTTP Basic-auth challenge panel for Nagios (/nagios/). The corpus served a
 * degenerate empty 401 there with no challenge header (incoherent — a 401 with no WWW-Authenticate reads
 * as faked). This owns_path override serves the authentic Apache `401 WWW-Authenticate: Basic realm=
 * "Nagios Access"` for ANY request (with or without an Authorization header, any credential pair), so it
 * is not a differential oracle and never authenticates: no cookie, no redirect, no auth-success witness.
 *
 * (Tomcat /manager/html was intentionally NOT given a 401 wall — the corpus already serves a rich,
 * persona-coherent Tomcat Web Application Manager page there, which is stronger high-interaction bait than
 * a challenge; see NewPageRoutingTest::test_tomcat_manager_enriches_existing_bundle.)
 */
final class NagiosBasicAuthPanelTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index;

    private function engine(): Honeypot
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return new Honeypot(
            new PhpArrayStore(self::$index),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'high',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
    }

    private static function header(object $resp, string $name): ?string
    {
        foreach ($resp->headers as $k => $v) {
            if (strcasecmp($k, $name) === 0) {
                return (string) $v;
            }
        }

        return null;
    }

    public function test_nagios_serves_a_basic_auth_challenge(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/nagios/', '', [], null, 'x.test'));
        self::assertNotNull($r);
        self::assertSame(401, $r->status);
        self::assertSame('Basic realm="Nagios Access"', self::header($r, 'WWW-Authenticate'));
        self::assertStringContainsString('Authorization Required', $r->body);
        self::assertStringContainsString('iso-8859-1', self::header($r, 'Content-Type') ?? '');
    }

    /**
     * The never-authenticate guarantee: a submitted credential (even a vendor default) gets the IDENTICAL
     * 401 challenge an uncredentialed request gets — no pair is ever accepted, so there is no oracle.
     *
     * @dataProvider credentials
     */
    public function test_submitted_credentials_never_authenticate(string $authPair): void
    {
        $engine = $this->engine();
        $bare = $engine->respond(new RequestContext('GET', '/nagios/', '', [], null, 'x.test'));
        $withCreds = $engine->respond(new RequestContext('GET', '/nagios/', '',
            ['Authorization' => 'Basic ' . base64_encode($authPair)], null, 'x.test'));
        self::assertNotNull($bare);
        self::assertNotNull($withCreds);
        self::assertSame(401, $withCreds->status, 'a credentialed request must still be challenged');
        self::assertSame($bare->body, $withCreds->body, 'credentialed and bare responses must be identical (no oracle)');
        self::assertNull(self::header($withCreds, 'Set-Cookie'), 'a challenge never mints a session');
        self::assertNull(self::header($withCreds, 'Location'), 'a challenge never redirects');
    }

    /** @return array<string,array{0:string}> */
    public function credentials(): array
    {
        return [
            'default'   => ['nagiosadmin:nagiosadmin'],
            'root-root' => ['root:root'],
            'admin'     => ['admin:admin'],
        ];
    }

    public function test_body_never_reflects_submitted_credentials(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/nagios/', '',
            ['Authorization' => 'Basic ' . base64_encode('CANARYuser:CANARYpass')], null, 'x.test'));
        self::assertNotNull($r);
        self::assertStringNotContainsString('CANARYuser', $r->body);
        self::assertStringNotContainsString('CANARYpass', $r->body);
    }
}
