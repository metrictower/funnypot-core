<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * A declined attack on a path serves exactly what the same request without its payload gets, through the
 * same guards: a hostile parameter never turns the path's decoy into a 404 and never unlocks a response
 * the bare request would not get. Full compiled corpus.
 */
final class AttackDeclineBaselineTest extends TestCase
{
    private const HOST = '127.0.0.1:18170';
    private const XSS = 'id=%3Cscript%3Ealert(1)%3C%2Fscript%3E-fp0777canary';

    private static function engine(?Observer $observer = null, bool $gateOpen = true): Honeypot
    {
        $config = new Config(
            'respond',
            $gateOpen ? static function (RequestContext $r): bool {
                return true;
            } : null,
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'critical',
            65536,
            0,
            0,
            true,
            null,
            null,
            null,
            'fp0769-lab',
            [],
            true,
            null,
            null,
            null,
            'fp0769-lab-deploy-seed'
        );

        return Honeypot::default($config, $observer);
    }

    private static function request(string $method, string $path, string $query = ''): RequestContext
    {
        return new RequestContext($method, $path, $query, ['user-agent' => 'Mozilla/5.0', 'host' => self::HOST], null, self::HOST, 'http');
    }

    /** @return array{0:int,1:?string,2:string}|null */
    private static function shape(?SynthesizedResponse $r): ?array
    {
        return $r === null ? null : [$r->status, $r->headers['Content-Type'] ?? null, $r->body];
    }

    private static function counter(bool $allow = true): Observer
    {
        return new class ($allow) implements Observer {
            /** @var bool */
            private $allow;
            /** @var int */
            public $detections = 0;
            /** @var int */
            public $outcomes = 0;

            public function __construct(bool $allow)
            {
                $this->allow = $allow;
            }

            public function onDetection(RequestContext $r, Detection $detection): void
            {
                $this->detections++;
            }

            public function shouldRespond(RequestContext $r, Detection $detection): bool
            {
                return $this->allow;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
            {
                $this->outcomes++;
            }
        };
    }

    public function test_declined_xss_serves_what_the_bare_request_gets(): void
    {
        $engine = self::engine();
        $bare = $engine->respond(self::request('GET', '/wp-login.php'));
        $attack = $engine->respond(self::request('GET', '/wp-login.php', self::XSS));

        self::assertNotNull($bare);
        self::assertSame(self::shape($bare), self::shape($attack), 'the decoy must not change because of the payload');
        self::assertStringNotContainsString('fp0777canary', $attack->body);
        self::assertContains('attack-xss', $attack->satisfies->templateIds(), 'consumers still see the attack');
        self::assertSame(FakeHandle::KIND_ROUTE, $attack->servedBy->kind);
        self::assertSame('attack-class', $engine->classify(self::request('GET', '/wp-login.php', self::XSS), \Funnypot\Core\SiteProfile::empty())->classification);
    }

    /** @return array<string,array{0:string,1:string,2:string}> */
    public function guardedProvider(): array
    {
        return [
            'HEAD wp-login never gets the login-success bundle' => ['HEAD', '/wp-login.php', self::XSS],
            'admin-ajax declines like the bare request' => ['GET', '/wp-admin/admin-ajax.php', 'action=%3Cscript%3Ex%3C%2Fscript%3E'],
            'the root needs a probe signature like the bare request' => ['GET', '/', 'q=%3Cscript%3Ex%3C%2Fscript%3E'],
            'a path whose own decoy is an attack rule' => ['GET', '/wp-admin', 'q=%3Cscript%3Ex%3C%2Fscript%3E'],
            'an etcd path whose own decoy is an attack rule' => ['GET', '/v3/kv/range', 'q=%3Cscript%3Ex%3C%2Fscript%3E'],
        ];
    }

    /** @dataProvider guardedProvider */
    public function test_payload_free_fallback_matches_the_bare_request(string $method, string $path, string $query): void
    {
        $engine = self::engine();

        self::assertSame(
            self::shape($engine->respond(self::request($method, $path))),
            self::shape($engine->respond(self::request($method, $path, $query))),
            "{$method} {$path}"
        );
    }

    public function test_closed_gate_and_veto_still_decline(): void
    {
        self::assertNull(self::engine(null, false)->respond(self::request('GET', '/wp-login.php', self::XSS)));
        self::assertNull(self::engine(self::counter(false))->respond(self::request('GET', '/wp-login.php', self::XSS)));
    }

    /** @return array<string,array{0:string,1:string,2:string}> */
    public function attackProvider(): array
    {
        return [
            'served fallback' => ['GET', '/wp-login.php', self::XSS],
            'declined fallback (HEAD)' => ['HEAD', '/wp-login.php', self::XSS],
            'declined fallback (root)' => ['GET', '/', 'q=%3Cscript%3Ex%3C%2Fscript%3E'],
            'neutral attack decoy' => ['GET', '/wp-admin', 'q=%3Cscript%3Ex%3C%2Fscript%3E'],
            'bare restricted file' => ['GET', '/wp-config.php', ''],
            'served by its own rule' => ['GET', '/viewfile.php', 'file=../../../../var/www/nothing'],
        ];
    }

    /** @dataProvider attackProvider */
    public function test_each_callback_fires_exactly_once(string $method, string $path, string $query): void
    {
        $observer = self::counter();
        self::engine($observer)->respond(self::request($method, $path, $query));

        self::assertSame(1, $observer->detections, 'onDetection');
        self::assertSame(1, $observer->outcomes, 'onOutcome');
    }

    public function test_an_attack_served_by_its_own_rule_is_unchanged(): void
    {
        $r = self::engine()->respond(self::request('GET', '/viewfile.php', 'file=../../../../etc/passwd'));

        self::assertNotNull($r);
        self::assertStringContainsString('root:', $r->body);
    }
}
