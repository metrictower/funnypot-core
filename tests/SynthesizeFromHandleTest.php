<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * synthesizeFromHandle() must be interchangeable with synthesize(). If it ever diverges, an adapter
 * carrying the handle across a package boundary silently serves a different fake than the one the
 * engine would have built — and nothing else would notice.
 */
final class SynthesizeFromHandleTest extends TestCase
{
    private function engine(): Honeypot
    {
        return Honeypot::default();
    }

    public function test_it_produces_the_byte_identical_response_synthesize_would(): void
    {
        $engine = $this->engine();
        $profile = SiteProfile::empty();
        $seed = 'seed-fixed';

        $verdict = $engine->classify(new RequestContext('GET', '/.git/config', '', [], null, 'example.com'), $profile);
        self::assertNotNull($verdict->fakeHandle, 'fixture must produce a handle');

        $viaVerdict = $engine->synthesize($verdict, $profile, $seed);
        $viaHandle = $engine->synthesizeFromHandle($verdict->fakeHandle, $profile, $seed);

        self::assertNotNull($viaVerdict);
        self::assertNotNull($viaHandle);
        self::assertSame($viaVerdict->status, $viaHandle->status);
        self::assertSame($viaVerdict->body, $viaHandle->body);

        // X-Request-Id is deliberately fresh per call — a real server issues a new one per
        // response, so two synthesize() calls differ too. Compare everything else.
        self::assertSame(
            $this->headersExceptRequestId($viaVerdict->headers),
            $this->headersExceptRequestId($viaHandle->headers)
        );
    }

    public function test_it_survives_a_serialization_round_trip(): void
    {
        $engine = $this->engine();
        $profile = SiteProfile::empty();
        $seed = 'seed-fixed';

        $verdict = $engine->classify(new RequestContext('GET', '/.git/config', '', [], null, 'example.com'), $profile);

        // What an adapter actually does: flatten the handle to a string, carry it across the
        // boundary in someone else's Verdict, rebuild it on the far side.
        $carried = FakeHandle::fromArray(json_decode((string) json_encode($verdict->fakeHandle->toArray()), true));

        $direct = $engine->synthesize($verdict, $profile, $seed);
        $roundTripped = $engine->synthesizeFromHandle($carried, $profile, $seed);

        self::assertNotNull($roundTripped);
        self::assertSame($direct->body, $roundTripped->body, 'a serialized handle must rebuild the same fake');
    }

    /** @param array<string,string> $headers @return array<string,string> */
    private function headersExceptRequestId(array $headers): array
    {
        unset($headers['X-Request-Id']);

        return $headers;
    }

    public function test_a_null_handle_degrades_to_null(): void
    {
        self::assertNull($this->engine()->synthesizeFromHandle(null, SiteProfile::empty(), 'seed'));
    }

    /**
     * A route handle carrying a FP-0157 paramIntent still round-trips byte-identically through the
     * position-blind port: the port has no request (no reflection evidence), so it decorates nothing,
     * and the intent — present, serialized and revalidated — cannot change the synthesized bytes.
     */
    public function test_a_param_intent_survives_the_hop_without_changing_port_bytes(): void
    {
        $index = [
            'schema' => 1,
            'manifest' => [],
            'templates' => ['t' => ['sev' => 'medium', 'tags' => [], 'name' => 'T']],
            'routes' => [
                'GET /shop' => ['b' => [[
                    's' => 200, 'bw' => ['<html', 'Welcome', '</body>'], 'h' => ['Content-Type' => 'text/html'],
                    'pid' => 'shop', 'sev' => 'medium', 'sig' => 0, 't' => ['t'],
                ]]],
            ],
        ];
        $config = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only', null, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, false);
        $config->isolatedOrigin = true;
        $config->reflectorAuthorizer = static function (RequestContext $r, string $class): bool { return true; };
        $config->paramReactivity = true;
        $engine = new Honeypot(new PhpArrayStore($index), $config);
        $profile = SiteProfile::empty();
        $seed = 'seed-fixed';

        $withIntent = $engine->classify(new RequestContext('GET', '/shop', 'q=hello', [], null, 'shop.example'), $profile);
        self::assertInstanceOf(ParamIntent::class, $withIntent->fakeHandle->paramIntent);
        $noQuery = $engine->classify(new RequestContext('GET', '/shop', '', [], null, 'shop.example'), $profile);
        self::assertNull($noQuery->fakeHandle->paramIntent);

        $carried = FakeHandle::fromArray(json_decode((string) json_encode($withIntent->fakeHandle->toArray()), true));
        self::assertInstanceOf(ParamIntent::class, $carried->paramIntent, 'intent survives the JSON hop');

        $viaVerdict = $engine->synthesize($withIntent, $profile, $seed);
        $viaHandle = $engine->synthesizeFromHandle($carried, $profile, $seed);
        $noIntent = $engine->synthesizeFromHandle($noQuery->fakeHandle, $profile, $seed);

        self::assertNotNull($viaVerdict);
        self::assertNotNull($viaHandle);
        self::assertNotNull($noIntent);
        // The port never decorates: intent-bearing and intent-free handles synthesize identical bodies.
        self::assertSame($noIntent->body, $viaVerdict->body, 'port must not react on the intent');
        self::assertSame($viaVerdict->body, $viaHandle->body, 'a serialized intent rebuilds the same port bytes');
    }
}
