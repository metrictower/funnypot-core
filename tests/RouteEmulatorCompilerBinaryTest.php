<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteBundleSynth;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * FP-0230 — the compiler must accept a binary (base64-at-rest) route rule and reject a corrupt one.
 *
 * A binary rule carries response.body_b64 (opaque image bytes) and NO response.body, so the binary
 * branch has to run before the empty-`response.body` throw and skip the directive/marker guards
 * (base64 with a `{{`-like sequence in an image byte run would otherwise trip assertKnownDirectives).
 * A corrupt asset must fail the build, never ship. Existing text templates must compile unchanged.
 */
final class RouteEmulatorCompilerBinaryTest extends TestCase
{
    /** @param array<string,mixed> $doc @return array<string,mixed> */
    private function normalizeRoute(array $doc): array
    {
        $compiler = new RouteEmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'route-binary-test.yaml');
    }

    /** A 1x1 image-ish byte blob whose base64 tEXt-like region contains a `{{` that would trip the text guard. */
    private function binaryBytes(): string
    {
        // Deliberately include `{{grafana}}`-shaped bytes: proof the directive guard is skipped for bin.
        return "\x89PNG\r\n\x1a\n" . "{{taunt}}" . random_bytes(48) . "\x00\x00IEND\xaeB`\x82";
    }

    public function test_binary_rule_compiles_with_bin_flag_and_base64_body(): void
    {
        $bytes = $this->binaryBytes();
        $rule = $this->normalizeRoute([
            'id' => 'route-x-favicon',
            'new_page' => ['method' => 'GET', 'paths' => ['/x/favicon.ico']],
            'match' => ['pid' => ['route-x-favicon']],
            'response' => [
                'headers' => ['Content-Type' => 'image/png'],
                'body_b64' => base64_encode($bytes),
            ],
        ]);

        self::assertSame(1, $rule['bin'] ?? null, 'a binary rule must be stamped bin=1');
        self::assertSame(base64_encode($bytes), $rule['body'], 'the base64 is stored verbatim as the rule body');
        self::assertSame('image/png', $rule['headers']['Content-Type'] ?? null, 'headers still compile');
        // Round-trip: decoding the stored body yields the exact bytes, `{{taunt}}` and all.
        self::assertSame($bytes, base64_decode($rule['body'], true));
    }

    public function test_binary_rule_may_omit_response_body(): void
    {
        // The whole point of A2: no response.body, only body_b64 — must NOT trip the empty-body throw.
        $rule = $this->normalizeRoute([
            'id' => 'route-y-favicon',
            'match' => ['pid' => ['route-y-favicon']],
            'response' => ['body_b64' => base64_encode('icon-bytes')],
        ]);
        self::assertSame(1, $rule['bin'] ?? null);
    }

    public function test_binary_marker_flag_forces_binary_handling(): void
    {
        $rule = $this->normalizeRoute([
            'id' => 'route-z-favicon',
            'match' => ['pid' => ['route-z-favicon']],
            'response' => ['binary' => true, 'body_b64' => base64_encode('bytes')],
        ]);
        self::assertSame(1, $rule['bin'] ?? null);
    }

    public function test_invalid_base64_body_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/base64/i');
        $this->normalizeRoute([
            'id' => 'route-bad-favicon',
            'match' => ['pid' => ['route-bad-favicon']],
            'response' => ['body_b64' => 'not valid base64 !!!! @@@@'],
        ]);
    }

    public function test_empty_base64_body_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/base64/i');
        $this->normalizeRoute([
            'id' => 'route-empty-favicon',
            'match' => ['pid' => ['route-empty-favicon']],
            'response' => ['body_b64' => ''],
        ]);
    }

    public function test_both_body_and_body_b64_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/both present/i');
        $this->normalizeRoute([
            'id' => 'route-dual-favicon',
            'match' => ['pid' => ['route-dual-favicon']],
            'response' => ['body' => 'text', 'body_b64' => base64_encode('bytes')],
        ]);
    }

    public function test_text_route_still_compiles_unchanged(): void
    {
        // Regression: a normal text rule keeps the exact existing sequence (no bin flag).
        $rule = $this->normalizeRoute([
            'id' => 'route-text',
            'match' => ['pid' => ['route-text']],
            'response' => ['body' => 'hello {{persona.company.domain}}'],
        ]);
        self::assertArrayNotHasKey('bin', $rule);
        self::assertSame('hello {{persona.company.domain}}', $rule['body']);
    }

    public function test_text_route_with_empty_body_still_throws(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/response\.body is required/');
        $this->normalizeRoute([
            'id' => 'route-empty-text',
            'match' => ['pid' => ['route-empty-text']],
            'response' => ['headers' => ['Content-Type' => 'text/plain']],
        ]);
    }

    public function test_bundle_synth_stamps_bin_on_the_folded_bundle(): void
    {
        // A3: the new-page fragment bundle for a binary page must carry bin=1 so ResponseSynthesizer
        // bypasses minimal-synth. Drive RouteBundleSynth against a temp dir with a binary template.
        $dir = sys_get_temp_dir() . '/fp0230-synth-' . getmypid();
        @mkdir($dir);
        $yaml = "id: route-w-favicon\n"
            . "new_page:\n  method: GET\n  paths: ['/w/favicon.ico']\n  sig: 0\n  status: 200\n"
            . "  name: 'W favicon'\n  weight: 20\n"
            . "response:\n  headers: { Content-Type: 'image/x-icon' }\n"
            . "  body_b64: '" . base64_encode('icon') . "'\n";
        file_put_contents($dir . '/900-w-favicon.yaml', $yaml);

        $fragment = (new RouteBundleSynth())->fragment($dir);
        @unlink($dir . '/900-w-favicon.yaml');
        @rmdir($dir);

        $bundles = $fragment['routes']['GET /w/favicon.ico'] ?? [];
        self::assertCount(1, $bundles, 'the binary page must fold one bundle');
        self::assertSame(1, $bundles[0]['bin'] ?? null, 'the folded bundle must be stamped bin=1');
        self::assertSame(20, $bundles[0]['w'] ?? null, 'the persona weight rides along');
    }
}
