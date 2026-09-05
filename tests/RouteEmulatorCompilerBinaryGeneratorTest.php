<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteBundleSynth;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Response\BinaryBodyGeneratorRegistry;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * The `response.binary_generator` arm of the route DSL: a closed built-in ID (never a class,
 * callback or argument block), exclusive with body / body_b64, compiled to `bin=1` plus the ID, and
 * — the fail-safe that matters for a fleet on an older engine — a compiled `body` that is NOT strict
 * base64, so a runtime that predates generators declines to its 404 instead of serving a 200 empty
 * attachment. The `response` key set is closed at the same time, so an unknown key fails the build.
 */
final class RouteEmulatorCompilerBinaryGeneratorTest extends TestCase
{
    /** @param array<string,mixed> $doc @return array<string,mixed> */
    private function normalizeRoute(array $doc): array
    {
        $compiler = new RouteEmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'route-generator-test.yaml');
    }

    /** @param array<string,mixed> $response @return array<string,mixed> */
    private function generatorDoc(array $response): array
    {
        return [
            'id' => 'route-x-heapdump',
            'new_page' => ['method' => 'GET', 'paths' => ['/x/heapdump']],
            'response' => $response,
        ];
    }

    public function test_generator_rule_compiles_to_bin_with_the_closed_id(): void
    {
        $rule = $this->normalizeRoute($this->generatorDoc([
            'headers' => ['Content-Type' => 'application/octet-stream'],
            'binary_generator' => 'spring_hprof_v1',
        ]));

        self::assertSame(1, $rule['bin'] ?? null, 'a generator rule must be stamped bin=1');
        self::assertSame('spring_hprof_v1', $rule['binary_generator'] ?? null);
        self::assertSame('application/octet-stream', $rule['headers']['Content-Type'] ?? null);
        self::assertSame(['pid' => ['route-x-heapdump']], $rule['match'], 'new_page auto-fills the exact pid selector');
        // The exact compiled shape: pure data, no extra keys a runtime could misread (`_priority` is
        // the compile-time sort key compileDirs() strips before the artifact is written).
        self::assertSame(['id', 'match', 'body', 'headers', 'bin', 'binary_generator'], array_values(array_diff(array_keys($rule), ['_priority'])));
    }

    public function test_generator_rule_body_is_a_sentinel_an_old_runtime_declines_on(): void
    {
        $rule = $this->normalizeRoute($this->generatorDoc(['binary_generator' => 'spring_hprof_v1']));

        // The pre-generator bin branch ran exactly this decode and returned null on false.
        self::assertNotSame('', $rule['body'], 'an empty body is the hazard: base64_decode("", true) is "" and would serve a 200 empty attachment');
        self::assertSame('', base64_decode('', true), 'documents why an empty body is not a safe sentinel');
        self::assertFalse(base64_decode((string) ($rule['body'] ?? ''), true), 'the sentinel must be strict-base64-INVALID so an older runtime declines to 404');
        self::assertStringStartsWith(RouteEmulatorCompiler::GENERATOR_BODY_SENTINEL, $rule['body']);
    }

    public function test_generator_is_exclusive_with_body(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/exactly one of the three/');
        $this->normalizeRoute($this->generatorDoc(['body' => 'text', 'binary_generator' => 'spring_hprof_v1']));
    }

    public function test_generator_is_exclusive_with_body_b64(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/exactly one of the three/');
        $this->normalizeRoute($this->generatorDoc(['body_b64' => base64_encode('x'), 'binary_generator' => 'spring_hprof_v1']));
    }

    /** @return array<string,array{0:mixed}> */
    public static function rejectedGeneratorIds(): array
    {
        return [
            'unknown id' => ['spring_hprof_v2'],
            'leading space (no trim)' => [' spring_hprof_v1'],
            'trailing space (no trim)' => ['spring_hprof_v1 '],
            'wrong case' => ['Spring_Hprof_V1'],
            'empty' => [''],
            'null' => [null],
            'integer' => [1],
            'boolean' => [true],
            'class name' => ['Funnypot\\Core\\Response\\SpringHprofGenerator'],
            'mapping (would-be class + args)' => [['class' => 'SpringHprofGenerator', 'args' => ['size' => 1]]],
            'list' => [['spring_hprof_v1']],
        ];
    }

    /**
     * @dataProvider rejectedGeneratorIds
     * @param mixed $id
     */
    public function test_anything_but_an_exact_registered_id_is_rejected($id): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/unknown binary_generator/');
        $this->normalizeRoute($this->generatorDoc(['binary_generator' => $id]));
    }

    public function test_unknown_response_key_fails_the_build(): void
    {
        // A generator argument/options block can never ride along: the key set is closed.
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/unknown response key \'generator_args\'/');
        $this->normalizeRoute($this->generatorDoc([
            'binary_generator' => 'spring_hprof_v1',
            'generator_args' => ['size' => 1],
        ]));
    }

    public function test_unknown_response_key_is_rejected_on_a_text_rule_too(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/unknown response key \'status\'/');
        $this->normalizeRoute([
            'id' => 'route-text',
            'match' => ['pid' => ['route-text']],
            'response' => ['body' => 'hello', 'status' => 200],
        ]);
    }

    public function test_the_response_key_set_is_exactly_the_documented_five(): void
    {
        self::assertSame(['headers', 'body', 'body_b64', 'binary', 'binary_generator'], RouteEmulatorCompiler::RESPONSE_KEYS);
        // And the registry the compiler lints against is the one closed list.
        self::assertSame(['spring_hprof_v1'], BinaryBodyGeneratorRegistry::IDS);
        foreach (BinaryBodyGeneratorRegistry::IDS as $id) {
            self::assertNotNull(BinaryBodyGeneratorRegistry::default()->find($id), "every declared ID has a built-in: {$id}");
        }
    }

    public function test_every_allowed_key_still_compiles(): void
    {
        $text = $this->normalizeRoute([
            'id' => 'route-text',
            'match' => ['pid' => ['route-text']],
            'response' => ['headers' => ['Content-Type' => 'text/plain'], 'body' => 'hello'],
        ]);
        self::assertArrayNotHasKey('bin', $text);
        self::assertArrayNotHasKey('binary_generator', $text);

        $b64 = $this->normalizeRoute([
            'id' => 'route-icon',
            'match' => ['pid' => ['route-icon']],
            'response' => ['headers' => ['Content-Type' => 'image/png'], 'binary' => true, 'body_b64' => base64_encode('icon')],
        ]);
        self::assertSame(1, $b64['bin'] ?? null);
        self::assertArrayNotHasKey('binary_generator', $b64, 'body_b64 compiles exactly as before');
        self::assertSame('icon', base64_decode($b64['body'], true));
    }

    public function test_bundle_synth_stamps_bin_on_a_generator_page(): void
    {
        $dir = sys_get_temp_dir() . '/fp0166-synth-' . getmypid();
        @mkdir($dir);
        $yaml = "id: route-w-heapdump\n"
            . "new_page:\n  method: GET\n  paths: ['/w/heapdump', '/w/actuator/heapdump']\n  status: 200\n"
            . "  severity: high\n  name: 'W heap dump'\n  typed_headers: { Content-Type: [application/octet-stream] }\n"
            . "response:\n  headers: { Content-Type: 'application/octet-stream' }\n"
            . "  binary_generator: spring_hprof_v1\n";
        file_put_contents($dir . '/900-w-heapdump.yaml', $yaml);

        $fragment = (new RouteBundleSynth())->fragment($dir);
        @unlink($dir . '/900-w-heapdump.yaml');
        @rmdir($dir);

        self::assertCount(2, $fragment['routes'], 'one key per path');
        foreach (['GET /w/heapdump', 'GET /w/actuator/heapdump'] as $key) {
            $bundles = $fragment['routes'][$key] ?? [];
            self::assertCount(1, $bundles, "{$key} folds one bundle");
            self::assertSame(1, $bundles[0]['bin'] ?? null, "{$key} bundle must be stamped bin=1 so MINIMAL cannot emit an empty-body substitute");
            self::assertSame([], $bundles[0]['bw'], 'a generated page carries no body words');
            self::assertSame(['Content-Type' => ['application/octet-stream']], $bundles[0]['th']);
        }
    }

    public function test_the_shipped_heapdump_rule_has_the_generator_shape(): void
    {
        $rules = require __DIR__ . '/../resources/compiled/funnypot-routes.php';
        $rule = null;
        foreach ($rules as $r) {
            if (($r['id'] ?? '') === 'route-actuator-heapdump') {
                $rule = $r;
            }
        }
        self::assertNotNull($rule, 'route-actuator-heapdump must be compiled');
        self::assertSame(1, $rule['bin'] ?? null);
        self::assertSame('spring_hprof_v1', $rule['binary_generator'] ?? null);
        self::assertFalse(base64_decode((string) $rule['body'], true), 'the compiled artifact carries the old-runtime sentinel');
        self::assertSame(['Content-Type' => 'application/octet-stream'], $rule['headers'], 'raw .hprof bytes: no Content-Disposition, no charset (what Spring Boot streams)');
        self::assertArrayNotHasKey('taunt', $rule);
        self::assertArrayNotHasKey('set_cookie', $rule);
    }
}
