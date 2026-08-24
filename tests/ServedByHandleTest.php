<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Config;
use Funnypot\Detection;
use Funnypot\FakeHandle;
use Funnypot\Honeypot;
use Funnypot\Http\ResponseEmitter;
use Funnypot\RequestContext;
use Funnypot\Response\Style;
use Funnypot\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * The winning decoy handle is surfaced to the app on SynthesizedResponse::$servedBy (FP-0001) so
 * the debug tooling can name which decoy served a request — but it is INTERNAL. ResponseEmitter
 * writes only ->headers + ->body; $servedBy is a distinct property it never touches. A leaked
 * decoy id in a served response would let an attacker fingerprint the honeypot, so these tests pin
 * both that servedBy IS set on a decoy hit and that its id NEVER reaches the served bytes/headers.
 */
final class ServedByHandleTest extends TestCase
{
    private function respondEngine(): Honeypot
    {
        $gate = static function (RequestContext $r): bool {
            return true;
        };

        return Honeypot::default(new Config(
            'respond',
            $gate,
            'matched-only',
            null,
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            0,
            0,
            true // attackEmulation
        ));
    }

    public function test_served_by_is_set_on_a_route_tier_hit(): void
    {
        $resp = $this->respondEngine()->respond(new RequestContext('GET', '/.git/config'));

        self::assertNotNull($resp);
        self::assertInstanceOf(FakeHandle::class, $resp->servedBy);
        self::assertSame(FakeHandle::KIND_ROUTE, $resp->servedBy->kind);
        self::assertSame('GET /.git/config', $resp->servedBy->key);
    }

    public function test_served_by_is_set_on_an_attack_tier_hit(): void
    {
        // An LFI payload on an unrouted path triggers attack emulation (the respondAttack branch).
        $resp = $this->respondEngine()->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd'));

        self::assertNotNull($resp);
        self::assertInstanceOf(FakeHandle::class, $resp->servedBy);
        self::assertSame(FakeHandle::KIND_ATTACK, $resp->servedBy->kind);
        self::assertNotSame('', (string) $resp->servedBy->ruleId);
    }

    /**
     * The load-bearing invariant: the decoy id never appears in the bytes/headers a client sees.
     * ResponseEmitter emits exactly ->headers + ->body, so asserting the id is absent from both is
     * proof it can never be emitted.
     */
    public function test_served_by_id_never_reaches_served_bytes_or_headers(): void
    {
        $engine = $this->respondEngine();
        $cases = array(
            $engine->respond(new RequestContext('GET', '/.git/config')),
            $engine->respond(new RequestContext('GET', '/nope', 'file=../../etc/passwd')),
        );

        foreach ($cases as $resp) {
            self::assertNotNull($resp);
            $handle = $resp->servedBy;
            self::assertNotNull($handle);
            $id = $handle->kind === FakeHandle::KIND_ROUTE ? (string) $handle->key : (string) $handle->ruleId;
            self::assertNotSame('', $id);

            self::assertStringNotContainsString($id, $resp->body, 'decoy id absent from body');
            foreach ($resp->headers as $name => $value) {
                self::assertStringNotContainsString($id, (string) $name, 'decoy id absent from header name');
                self::assertStringNotContainsString($id, (string) $value, 'decoy id absent from header value');
            }
        }
    }

    /**
     * ResponseEmitter is the one serve path. Emitting a response whose servedBy carries a sentinel
     * id must not put that sentinel into the output bytes — servedBy is structurally outside the
     * emitted surface (only ->headers + ->body are written).
     */
    public function test_emitter_does_not_write_served_by(): void
    {
        $sentinel = 'attack-SENTINEL-do-not-leak';
        $resp = new SynthesizedResponse(200, array('Content-Type' => 'text/plain'), 'inert body', Detection::none());
        $resp->servedBy = FakeHandle::attack($sentinel);

        // Emit writes http_response_code()/header() (no ob output) then echoes the body. Capture the
        // echoed bytes; header() emits nothing observable here. The sentinel must be nowhere in them.
        ob_start();
        @ResponseEmitter::emit($resp);
        $emitted = (string) ob_get_clean();

        self::assertStringNotContainsString($sentinel, $emitted);
        self::assertSame('inert body', $emitted);
        // The app can still read the handle off the response object.
        self::assertSame($sentinel, $resp->servedBy->ruleId);
    }
}
