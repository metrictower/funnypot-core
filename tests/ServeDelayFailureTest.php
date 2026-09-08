<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

final class ServeDelayFailureTest extends TestCase
{
    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function test_route_response_survives_jitter_error_with_base_delay_and_identical_bytes(): void
    {
        $this->installEntropySpies();

        ServeDelayEntropySpy::reset(false);
        $ordinary = $this->config(17, 5)->serveDelayMicros();
        self::assertGreaterThanOrEqual(17000, $ordinary);
        self::assertLessThanOrEqual(22000, $ordinary);
        self::assertSame(1, ServeDelayEntropySpy::$jitterCalls);
        self::assertSame(0, ServeDelayEntropySpy::$jitterErrors);

        $controlObserver = new ServeDelayOutcomeSpy();
        ServeDelayEntropySpy::reset(false);
        $control = (new Honeypot($this->store(), $this->config(17, 0), $controlObserver))
            ->respond(new RequestContext('GET', '/multi'));
        $controlByteCalls = ServeDelayEntropySpy::$byteCalls;

        $failureObserver = new ServeDelayOutcomeSpy();
        ServeDelayEntropySpy::reset(true);
        $failure = (new Honeypot($this->store(), $this->config(17, 5), $failureObserver))
            ->respond(new RequestContext('GET', '/multi'));

        self::assertNotNull($control);
        self::assertNotNull($failure);
        self::assertNotNull($control->servedBy);
        self::assertNotNull($failure->servedBy);
        self::assertSame(FakeHandle::KIND_ROUTE, $control->servedBy->kind);
        self::assertSame(FakeHandle::KIND_ROUTE, $failure->servedBy->kind);
        self::assertSame(17000, $control->delayMicros);
        self::assertSame(17000, $failure->delayMicros);
        self::assertSame([Outcome::SERVED], $controlObserver->outcomes);
        self::assertSame([Outcome::SERVED], $failureObserver->outcomes);
        self::assertSame(1, ServeDelayEntropySpy::$jitterCalls, 'the failing draw is attempted exactly once');
        self::assertSame(1, ServeDelayEntropySpy::$jitterErrors, 'the forced Error path is non-vacuous');
        self::assertSame($controlByteCalls, ServeDelayEntropySpy::$byteCalls);
        self::assertGreaterThan(0, array_sum($controlByteCalls));
        $this->assertSameEnvelope($control, $failure);
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function test_attack_response_survives_jitter_error_with_zero_base_and_identical_bytes(): void
    {
        $this->installEntropySpies();
        $request = new RequestContext('GET', '/nope', 'file=../../etc/passwd');

        $controlObserver = new ServeDelayOutcomeSpy();
        ServeDelayEntropySpy::reset(false);
        $control = (new Honeypot($this->compiledStore(), $this->config(0, 0, true), $controlObserver))
            ->respond($request);
        $controlByteCalls = ServeDelayEntropySpy::$byteCalls;

        $failureObserver = new ServeDelayOutcomeSpy();
        ServeDelayEntropySpy::reset(true);
        $failure = (new Honeypot($this->compiledStore(), $this->config(0, 9, true), $failureObserver))
            ->respond($request);

        self::assertNotNull($control);
        self::assertNotNull($failure);
        self::assertNotNull($control->servedBy);
        self::assertNotNull($failure->servedBy);
        self::assertSame(FakeHandle::KIND_ATTACK, $control->servedBy->kind);
        self::assertSame(FakeHandle::KIND_ATTACK, $failure->servedBy->kind);
        self::assertSame(0, $control->delayMicros);
        self::assertSame(0, $failure->delayMicros);
        self::assertSame([Outcome::SERVED], $controlObserver->outcomes);
        self::assertSame([Outcome::SERVED], $failureObserver->outcomes);
        self::assertSame(1, ServeDelayEntropySpy::$jitterCalls, 'positive jitter reaches the forced Error path');
        self::assertSame(1, ServeDelayEntropySpy::$jitterErrors);
        self::assertSame($controlByteCalls, ServeDelayEntropySpy::$byteCalls);
        self::assertGreaterThan(0, array_sum($controlByteCalls));
        $this->assertSameEnvelope($control, $failure);
    }

    private function config(int $latencyMs, int $jitterMs, bool $attackEmulation = false): Config
    {
        return new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'serve-delay-fixture'; },
            'coherent',
            Style::MINIMAL,
            'high',
            65536,
            $latencyMs,
            $jitterMs,
            $attackEmulation
        );
    }

    private function store(): PhpArrayStore
    {
        return new PhpArrayStore([
            'schema' => 1,
            'manifest' => [],
            'templates' => [
                't-a' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'A'],
                't-b' => ['sev' => 'low', 'tags' => ['exposure'], 'name' => 'B'],
            ],
            'routes' => [
                'GET /multi' => ['b' => [
                    ['s' => 200, 'bw' => ['AAA'], 'nf' => [], 'h' => [], 'pid' => 'pa', 'sev' => 'low', 'sig' => 0, 't' => ['t-a']],
                    ['s' => 200, 'bw' => ['BBB'], 'nf' => [], 'h' => [], 'pid' => 'pb', 'sev' => 'low', 'sig' => 0, 't' => ['t-b']],
                ]],
            ],
        ]);
    }

    private function compiledStore(): PhpArrayStore
    {
        return new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.php');
    }

    private function assertSameEnvelope(SynthesizedResponse $expected, SynthesizedResponse $actual): void
    {
        self::assertSame($expected->status, $actual->status);
        self::assertSame($expected->headers, $actual->headers);
        self::assertSame($expected->body, $actual->body);
    }

    private function installEntropySpies(): void
    {
        eval(<<<'PHP'
namespace Funnypot\Core {
    function random_int($min, $max) {
        \Funnypot\Core\Tests\ServeDelayEntropySpy::$jitterCalls++;
        if (\Funnypot\Core\Tests\ServeDelayEntropySpy::$armed) {
            \Funnypot\Core\Tests\ServeDelayEntropySpy::$jitterErrors++;
            throw new \Error('fp-0285-forced-jitter-error');
        }
        return \random_int($min, $max);
    }

    function random_bytes($length) {
        return \Funnypot\Core\Tests\ServeDelayEntropySpy::bytes($length, 'core');
    }
}

namespace Funnypot\Core\Synthesis {
    function random_bytes($length) {
        return \Funnypot\Core\Tests\ServeDelayEntropySpy::bytes($length, 'synthesis');
    }
}
PHP
        );
    }
}

final class ServeDelayEntropySpy
{
    /** @var bool */
    public static $armed = false;

    /** @var int */
    public static $jitterCalls = 0;

    /** @var int */
    public static $jitterErrors = 0;

    /** @var array<string,int> */
    public static $byteCalls = ['core' => 0, 'synthesis' => 0];

    /** @var int */
    private static $byteSequence = 0;

    public static function reset(bool $armed): void
    {
        self::$armed = $armed;
        self::$jitterCalls = 0;
        self::$jitterErrors = 0;
        self::$byteCalls = ['core' => 0, 'synthesis' => 0];
        self::$byteSequence = 0;
    }

    public static function bytes(int $length, string $source): string
    {
        self::$byteCalls[$source]++;
        $bytes = '';
        while (strlen($bytes) < $length) {
            $bytes .= hash('sha256', 'serve-delay-' . self::$byteSequence++, true);
        }

        return substr($bytes, 0, $length);
    }
}

final class ServeDelayOutcomeSpy implements Observer
{
    /** @var string[] */
    public $outcomes = [];

    public function onDetection(RequestContext $r, Detection $detection): void
    {
    }

    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
        $this->outcomes[] = $reason;
    }
}
