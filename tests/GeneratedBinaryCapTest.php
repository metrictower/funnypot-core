<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Observer;
use Funnypot\Core\Outcome;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Response\BinaryBodyGenerator;
use Funnypot\Core\Response\BinaryBodyGeneratorRegistry;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Throwable;
use TypeError;

/**
 * The emulator-side contract for a generated binary body, pinned with injected generators: exactly
 * 65 536 bytes serves, 65 537 declines, and so do an empty result, a null, a throw of any kind, a
 * type-violating return and an unregistered ID — always as a clean null (host 404), never truncated,
 * never a 5xx, and never a fallback to decoding the sentinel body. A lower operator maxBodyBytes then
 * declines the complete artifact at the facade.
 */
final class GeneratedBinaryCapTest extends TestCase
{
    /** @param mixed $value a string/null to return, a Throwable to throw, or anything else (a type violation) */
    private function generatorReturning($value): BinaryBodyGenerator
    {
        return new class($value) implements BinaryBodyGenerator {
            /** @var mixed */
            private $value;

            /** @param mixed $value */
            public function __construct($value)
            {
                $this->value = $value;
            }

            public function generate(DirectiveRenderer $renderer, int $seed): ?string
            {
                if ($this->value instanceof Throwable) {
                    throw $this->value;
                }

                return $this->value;
            }
        };
    }

    /** @param array<string,BinaryBodyGenerator> $generators */
    private function emulator(array $generators): RouteTemplateEmulator
    {
        $set = new RouteTemplateSet([[
            'id' => 'route-gen',
            'match' => ['pid' => ['route-gen']],
            'body' => '!fake',
            'headers' => ['Content-Type' => 'application/octet-stream'],
            'bin' => 1,
            'binary_generator' => 'fake',
        ]]);

        return new RouteTemplateEmulator($set, null, false, [], new BinaryBodyGeneratorRegistry($generators));
    }

    /** @return array<string,mixed> */
    private function bundle(): array
    {
        return ['pid' => 'route-gen', 't' => ['route-gen'], 'bw' => []];
    }

    public function test_exactly_the_ceiling_serves_intact(): void
    {
        $bytes = str_repeat("\x00\xff", RouteTemplateEmulator::MAX_GENERATED_BODY_BYTES / 2);
        self::assertSame(65536, strlen($bytes));
        self::assertSame(65536, RouteTemplateEmulator::MAX_GENERATED_BODY_BYTES);
        foreach ([Style::MINIMAL, Style::REALISTIC, Style::TAUNT] as $style) {
            $content = $this->emulator(['fake' => $this->generatorReturning($bytes)])->render($this->bundle(), $style, 1);
            self::assertNotNull($content, "{$style}: an artifact of exactly the ceiling must serve");
            self::assertSame($bytes, $content->body, "{$style}: served verbatim, no truncation, no taunt/injection");
            self::assertSame(['Content-Type' => 'application/octet-stream'], $content->headers);
        }
    }

    /** @return array<string,array{0:mixed}> */
    public static function declines(): array
    {
        return [
            'one byte over the ceiling' => [str_repeat('a', 65537)],
            'far over the ceiling' => [str_repeat('a', 200000)],
            'empty string' => [''],
            'null (explicit decline)' => [null],
            'RuntimeException' => [new RuntimeException('boom')],
            'TypeError (an Error, not an Exception)' => [new TypeError('bad')],
            'type-violating return' => [12345],
            'array return' => [['not', 'bytes']],
        ];
    }

    /**
     * @dataProvider declines
     * @param mixed $value
     */
    public function test_every_bad_result_declines_cleanly($value): void
    {
        foreach ([Style::MINIMAL, Style::REALISTIC, Style::TAUNT] as $style) {
            self::assertNull($this->emulator(['fake' => $this->generatorReturning($value)])->render($this->bundle(), $style, 1), "{$style}: must decline, never truncate or throw");
        }
    }

    public function test_unregistered_id_declines_and_never_falls_back_to_the_sentinel_body(): void
    {
        // The rule names 'fake' but the registry only knows 'other': decline. The sentinel `!fake`
        // body must not be decoded as a base64 fallback (it is not base64, so that would also be
        // null — the point is the branch order: generator first, no second chance).
        $emu = $this->emulator(['other' => $this->generatorReturning('bytes')]);
        self::assertNull($emu->render($this->bundle(), Style::REALISTIC, 1));
        self::assertNull($this->emulator([])->render($this->bundle(), Style::REALISTIC, 1), 'an empty registry declines');
    }

    public function test_the_default_registry_serves_the_shipped_heapdump_and_an_empty_one_declines_it(): void
    {
        $set = RouteTemplateSet::fromPackage();
        $bundle = ['pid' => 'route-actuator-heapdump', 't' => ['route-actuator-heapdump'], 'bw' => []];

        $default = new RouteTemplateEmulator($set);
        $content = $default->render($bundle, Style::MINIMAL, 9);
        self::assertNotNull($content, 'the no-arg construction site (CI render gates) must serve generated bodies');
        self::assertStringStartsWith("JAVA PROFILE 1.0.2\0", $content->body);

        $empty = new RouteTemplateEmulator($set, null, false, [], new BinaryBodyGeneratorRegistry([]));
        self::assertNull($empty->render($bundle, Style::MINIMAL, 9), 'no generator, no bytes — the sentinel body is never served');
    }

    public function test_generator_receives_the_renderer_and_the_render_seed(): void
    {
        $seen = [];
        $gen = new class($seen) implements BinaryBodyGenerator {
            /** @var array<int,mixed> */
            public $seen;

            /** @param array<int,mixed> $seen */
            public function __construct(array &$seen)
            {
                $this->seen = &$seen;
            }

            public function generate(DirectiveRenderer $renderer, int $seed): ?string
            {
                $this->seen[] = [$renderer, $seed];

                return 'ok';
            }
        };
        $renderer = new DirectiveRenderer(4242);
        $set = new RouteTemplateSet([['id' => 'route-gen', 'match' => ['pid' => ['route-gen']], 'body' => '!fake', 'headers' => [], 'bin' => 1, 'binary_generator' => 'fake']]);
        $emu = new RouteTemplateEmulator($set, $renderer, false, [], new BinaryBodyGeneratorRegistry(['fake' => $gen]));
        self::assertSame('ok', $emu->render($this->bundle(), Style::REALISTIC, 31337)->body);
        self::assertCount(1, $seen);
        self::assertSame($renderer, $seen[0][0], 'the emulator hands its own configured renderer through (the deploy persona seed rides with it)');
        self::assertSame(31337, $seen[0][1]);
    }

    public function test_a_lower_operator_cap_declines_the_complete_artifact_at_the_facade(): void
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = static function (int $maxBodyBytes): Config {
            return new Config(
                'respond',
                static function (RequestContext $r): bool { return true; },
                'matched-only',
                static function (RequestContext $r): string { return 'fixed'; },
                'coherent',
                Style::REALISTIC,
                'high',
                $maxBodyBytes
            );
        };
        $request = new RequestContext('GET', '/actuator/heapdump');
        $spy = new class implements Observer {
            /** @var string[] */
            public $reasons = [];

            public function onDetection(RequestContext $r, Detection $detection): void
            {
            }

            public function shouldRespond(RequestContext $r, Detection $detection): bool
            {
                return true;
            }

            public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
            {
                $this->reasons[] = $reason;
            }
        };

        $served = (new Honeypot($store, $config(65536), $spy))->respond($request);
        self::assertNotNull($served, 'the default cap serves the artifact');
        $len = strlen($served->body);
        self::assertGreaterThan(1024, $len);
        self::assertSame([Outcome::SERVED], $spy->reasons);

        $spy->reasons = [];
        self::assertNull((new Honeypot($store, $config(1024), $spy))->respond($request), 'a lower operator cap declines the whole artifact — never a truncated 200');
        self::assertSame([Outcome::OVER_CAP], $spy->reasons, 'the decline is reported as over-cap, not as unsynthesizable');

        self::assertNull((new Honeypot($store, $config($len - 1)))->respond($request), 'one byte under the artifact declines');
        self::assertNotNull((new Honeypot($store, $config($len)))->respond($request), 'the cap is inclusive');
    }
}
