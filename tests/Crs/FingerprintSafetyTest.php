<?php

declare(strict_types=1);

namespace Funnypot\Tests\Crs;

use Funnypot\Compiler\Crs\FingerprintGuard;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The fingerprint-safety gate: no upstream-detector signature may reach a served response.
 * An attacker who has fingerprinted ModSecurity/CRS before would recognise CRS's own
 * vocabulary (its `OWASP_CRS`/`paranoia-level` tags, a bare rule id, `libinjection`) and
 * conclude the reply is canned — the one thing the deception design must prevent.
 */
final class FingerprintSafetyTest extends TestCase
{
    private function guard(): FingerprintGuard
    {
        return FingerprintGuard::fromPackage();
    }

    /**
     * @dataProvider leakySignatures
     */
    public function test_scan_flags_every_detector_signature(string $text): void
    {
        self::assertNotEmpty($this->guard()->scan($text));
    }

    /** @return array<string,array{0:string}> */
    public static function leakySignatures(): array
    {
        return [
            'crs tag' => ['blocked by OWASP_CRS ruleset'],
            'modsecurity' => ['blocked by ModSecurity'],
            'libinjection' => ['detected via libinjection'],
            'paranoia level' => ['paranoia-level/1 triggered'],
            'bare rule id' => ['request matched rule 942100'],
            'anomaly score' => ['inbound_anomaly_score exceeded'],
        ];
    }

    /**
     * @dataProvider benignBodies
     */
    public function test_scan_passes_plausible_response_text(string $text): void
    {
        self::assertSame([], $this->guard()->scan($text));
    }

    /** @return array<string,array{0:string}> */
    public static function benignBodies(): array
    {
        return [
            'sql error' => ["You have an error in your SQL syntax; check the manual near '' at line 1"],
            'passwd' => ['root:x:0:0:root:/root:/bin/bash'],
            'html' => ['<h1>Search results</h1><p>No results found for your query.</p>'],
        ];
    }

    public function test_assert_response_clean_throws_on_a_leak(): void
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Fingerprint leak');
        $this->guard()->assertResponseClean('blocked: OWASP_CRS 942100', [], 'unit');
    }

    public function test_every_compiled_attack_response_is_clean(): void
    {
        $rules = require __DIR__ . '/../../resources/compiled/funnypot-attack.php';
        $guard = $this->guard();

        foreach ($rules as $rule) {
            $response = $rule['response'] ?? [];
            $hits = $guard->scan((string) ($response['body'] ?? ''));
            foreach ((array) ($response['headers'] ?? []) as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            self::assertSame([], $hits, "fingerprint leak in {$rule['id']}: " . implode(', ', $hits));
        }
    }

    public function test_the_ci_gate_script_passes_on_the_committed_artifact(): void
    {
        $root = dirname(__DIR__, 2);
        $script = $root . '/scripts/ci/check-fingerprint-safety.php';
        self::assertFileExists($script);

        exec('php ' . escapeshellarg($script) . ' 2>&1', $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
    }
}
