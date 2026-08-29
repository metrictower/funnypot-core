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
 * A per-request X-Request-Id is the front layer a real edge always adds. If any served branch
 * omits it, its absence marks that branch as the canned decoy — the exact tell a pentest used to
 * split our responses into a "real" tier and a discountable "fake" tier. Every branch that serves
 * bytes (attack templates + route emulators) must carry a unique 16-hex X-Request-Id, and the
 * shared stamp must never double it.
 */
final class XRequestIdEnvelopeTest extends TestCase
{
    private const HEX16 = '/^[0-9a-f]{16}$/';

    /** An attack-emulating engine through the full respond() facade. */
    private function inverter(string $ceiling = 'high', ?string $server = null, ?string $poweredBy = null): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');

        return new Honeypot($store, new Config(
            'respond',                                                    // mode
            static function (RequestContext $r): bool { return true; },   // gate
            'matched-only',                                               // pathScope
            null,                                                         // personaSeed
            'coherent',                                                   // personaBreadth
            Style::MINIMAL,                                               // responseStyle
            $ceiling,                                                     // severityCeiling
            65536,                                                        // maxBodyBytes
            0,                                                            // latencyMs
            0,                                                            // latencyJitterMs
            true,                                                         // attackEmulation
            null,                                                         // trustedBypass
            null,                                                         // killSwitch
            null,                                                         // probeSignature
            '',                                                           // seedSalt
            [],                                                           // exclude
            true,                                                         // nucleiReflection
            $server,                                                      // serverHeader
            $poweredBy                                                    // poweredBy
        ));
    }

    /** Count header keys equal to $name case-insensitively — an over-stamp would exceed one. */
    private function countHeader(array $headers, string $name): int
    {
        $needle = strtolower($name);
        $n = 0;
        foreach (array_keys($headers) as $key) {
            if (strtolower((string) $key) === $needle) {
                $n++;
            }
        }

        return $n;
    }

    private function assertHasRequestId($response): void
    {
        self::assertNotNull($response);
        self::assertArrayHasKey('X-Request-Id', $response->headers);
        self::assertMatchesRegularExpression(self::HEX16, $response->headers['X-Request-Id']);
        self::assertSame(1, $this->countHeader($response->headers, 'X-Request-Id'), 'exactly one X-Request-Id');
    }

    // --- attack-template branches (renderRule path — previously shipped NO X-Request-Id) ---

    public function test_lfi_branch_carries_a_unique_request_id(): void
    {
        $inv = $this->inverter();
        $a = $inv->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd'));
        $b = $inv->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd'));

        $this->assertHasRequestId($a);
        $this->assertHasRequestId($b);
        self::assertNotSame($a->headers['X-Request-Id'], $b->headers['X-Request-Id'], 'unique per response');
    }

    public function test_command_injection_branch_carries_a_unique_request_id(): void
    {
        // command-injection is 'critical'; raise the ceiling so the branch serves.
        $inv = $this->inverter('critical');
        $a = $inv->respond(new RequestContext('GET', '/nope', 'x=;id'));
        $b = $inv->respond(new RequestContext('GET', '/nope', 'x=;id'));

        $this->assertHasRequestId($a);
        self::assertStringContainsString('uid=0(root)', $a->body);
        $this->assertHasRequestId($b);
        self::assertNotSame($a->headers['X-Request-Id'], $b->headers['X-Request-Id']);
    }

    public function test_open_redirect_branch_carries_a_request_id_without_touching_status_or_location(): void
    {
        $inv = $this->inverter();
        $a = $inv->respond(new RequestContext('GET', '/nope', 'url=https://evil.example/phish'));
        $b = $inv->respond(new RequestContext('GET', '/nope', 'url=https://evil.example/phish'));

        $this->assertHasRequestId($a);
        // The envelope stamp must not disturb the app-chosen status or the reflected Location.
        self::assertSame(302, $a->status);
        self::assertSame('https://evil.example/phish', $a->headers['Location']);
        $this->assertHasRequestId($b);
        self::assertNotSame($a->headers['X-Request-Id'], $b->headers['X-Request-Id']);
    }

    public function test_xss_reflect_branch_carries_a_unique_request_id(): void
    {
        $inv = $this->inverter();
        $payload = '<script>alert(document.domain)</script>';
        $a = $inv->respond(new RequestContext('GET', '/nope', 'q=' . $payload));
        $b = $inv->respond(new RequestContext('GET', '/nope', 'q=' . $payload));

        $this->assertHasRequestId($a);
        self::assertStringContainsString($payload, $a->body);
        $this->assertHasRequestId($b);
        self::assertNotSame($a->headers['X-Request-Id'], $b->headers['X-Request-Id']);
    }

    public function test_attack_branch_also_carries_configured_server_identity(): void
    {
        // The shared stamp fills the coherent Server / X-Powered-By identity on the attack path too,
        // so header recon can't catch the attack fake missing a banner the route fakes present.
        $inv = $this->inverter('high', 'nginx/1.24.0', 'PHP/8.2.12');
        $a = $inv->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd'));

        $this->assertHasRequestId($a);
        self::assertSame('nginx/1.24.0', $a->headers['Server']);
        self::assertSame('PHP/8.2.12', $a->headers['X-Powered-By']);
    }

    // --- route-emulator branch (synthesizer path — must still stamp exactly one) ---

    public function test_route_emulator_branch_carries_a_unique_request_id(): void
    {
        $engine = Honeypot::default();
        $profile = SiteProfile::empty();
        $r = new RequestContext('GET', '/.git/config', '', [], null, 'example.com');

        $verdict = $engine->classify($r, $profile);
        self::assertNotNull($verdict->fakeHandle, 'fixture must produce a route handle');

        $a = $engine->synthesize($verdict, $profile, 'seed-fixed');
        $b = $engine->synthesize($verdict, $profile, 'seed-fixed');

        $this->assertHasRequestId($a);
        $this->assertHasRequestId($b);
        self::assertNotSame($a->headers['X-Request-Id'], $b->headers['X-Request-Id']);
    }
}
