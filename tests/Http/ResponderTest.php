<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Config;
use Funnypot\Core\Http\Responder;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
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
            'respond',                                                   // mode
            static function (RequestContext $r): bool { return true; }   // gate
        ));

        $response = Responder::forRequest($inverter, new RequestContext('GET', '/.git/config'));

        self::assertNotNull($response);
        self::assertStringContainsString('[core]', $response->body);
    }

    public function test_forwards_a_miss_as_null(): void
    {
        $inverter = new Honeypot($this->store(), new Config('respond'));

        self::assertNull(Responder::forRequest($inverter, new RequestContext('GET', '/totally/legit/page')));
    }
}
