<?php

declare(strict_types=1);

namespace Funnypot\Tests\Http;

use Funnypot\Config;
use Funnypot\Http\Responder;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Responder::forRequest() is a pure pass-through to respond() for callers with
 * no PSR-15/Laravel pipeline (e.g. a plain 404 handler) — this just proves it
 * forwards faithfully in both directions.
 */
final class ResponderTest extends TestCase
{
    private function store(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../../resources/compiled/nuclei-index.php');
    }

    public function test_forwards_a_hit_to_respond(): void
    {
        $inverter = new Honeypot($this->store(), new Config(
            mode: 'respond',
            gate: static fn (RequestContext $r): bool => true
        ));

        $response = Responder::forRequest($inverter, new RequestContext('GET', '/.git/config'));

        self::assertNotNull($response);
        self::assertStringContainsString('[core]', $response->body);
    }

    public function test_forwards_a_miss_as_null(): void
    {
        $inverter = new Honeypot($this->store(), new Config(mode: 'respond'));

        self::assertNull(Responder::forRequest($inverter, new RequestContext('GET', '/totally/legit/page')));
    }
}
