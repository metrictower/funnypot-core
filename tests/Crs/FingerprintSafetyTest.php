<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Crs;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
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

    public function test_every_compiled_route_response_is_clean(): void
    {
        $rules = require __DIR__ . '/../../resources/compiled/funnypot-routes.php';
        $guard = $this->guard();

        foreach ($rules as $rule) {
            // Route rules carry served content at top level (no `response` nesting); the dual-shape
            // fallback scans either shape. Cover body, headers, the Set-Cookie name, and the taunt
            // comment-syntax strings — every served byte an attacker can see.
            $response = $rule['response'] ?? $rule;
            $hits = $guard->scan((string) ($response['body'] ?? ''));
            foreach ((array) ($response['headers'] ?? []) as $name => $value) {
                $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
            }
            $hits = array_merge($hits, $guard->scan((string) ($rule['set_cookie'] ?? '')));
            if (isset($rule['taunt']) && is_array($rule['taunt'])) {
                foreach (['open', 'close', 'key'] as $part) {
                    $hits = array_merge($hits, $guard->scan((string) ($rule['taunt'][$part] ?? '')));
                }
            }
            self::assertSame([], $hits, "fingerprint leak in {$rule['id']}: " . implode(', ', $hits));
        }
    }

    public function test_every_compiled_param_response_is_clean(): void
    {
        $index = require __DIR__ . '/../../resources/compiled/funnypot-param.php';
        $guard = $this->guard();

        // The param artifact is bucketed; every served entry carries an attack-rule-shaped
        // `response`, so scan the body + headers of each — served content an attacker can see.
        foreach ((array) ($index['buckets'] ?? []) as $entries) {
            foreach ((array) $entries as $entry) {
                $response = $entry['response'] ?? [];
                $hits = $guard->scan((string) ($response['body'] ?? ''));
                foreach ((array) ($response['headers'] ?? []) as $name => $value) {
                    $hits = array_merge($hits, $guard->scan((string) $name), $guard->scan((string) $value));
                }
                self::assertSame([], $hits, "fingerprint leak in {$entry['id']}: " . implode(', ', $hits));
            }
        }
    }

    public function test_the_ci_gate_flags_a_leak_in_a_param_entry_response(): void
    {
        // A param artifact is bucketed, so the gate must flatten to its entries before scanning.
        // This one's entry response carries a detector signature — the gate must flag it. Written
        // to a scratch file and pointed at via --index; nothing lands in the repo.
        $index = [
            'schema' => 1,
            'buckets' => [
                'leak' => [[
                    'id' => 'param-leak-probe',
                    'severity' => 'high',
                    'tags' => ['param'],
                    'status' => 200,
                    'regex' => '^/leak/(?P<x>.+)$',
                    'captures' => ['x'],
                    'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
                ]],
            ],
        ];

        $root = dirname(__DIR__, 2);
        $script = $root . '/scripts/ci/check-fingerprint-safety.php';
        $tmp = tempnam(sys_get_temp_dir(), 'fp-param-') . '.php';
        file_put_contents($tmp, "<?php\n\nreturn " . var_export($index, true) . ";\n");

        try {
            exec('php ' . escapeshellarg($script) . ' --index=' . escapeshellarg($tmp) . ' 2>&1', $out, $code);
            self::assertSame(1, $code, 'a param entry leak must fail the gate: ' . implode("\n", $out));
            self::assertStringContainsString('fingerprint leak', implode("\n", $out));
        } finally {
            @unlink($tmp);
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

    public function test_the_ci_gate_flags_a_leak_in_a_branch_case_response(): void
    {
        // A `branch` rule serves its case/default responses when a case fires, so those bodies must
        // be scanned too. This rule's top-level response is clean but a branch case body carries a
        // detector signature — the exact leak the branch descent must catch. The artifact is written
        // to a scratch file and the gate is pointed at it via --index; nothing lands in the repo.
        $rule = [
            'id' => 'branch-leak-probe',
            'response' => ['headers' => [], 'body' => 'clean top-level body'],
            'behavior' => 'branch',
            'branch' => [
                'cases' => [[
                    'when' => ['in' => 'query', 'contains' => 'x'],
                    'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
                ]],
                'default' => ['response' => ['headers' => [], 'body' => 'clean default']],
            ],
        ];

        $root = dirname(__DIR__, 2);
        $script = $root . '/scripts/ci/check-fingerprint-safety.php';
        $tmp = tempnam(sys_get_temp_dir(), 'fp-branch-') . '.php';
        file_put_contents($tmp, "<?php\n\nreturn " . var_export([$rule], true) . ";\n");

        try {
            exec('php ' . escapeshellarg($script) . ' --index=' . escapeshellarg($tmp) . ' 2>&1', $out, $code);
            self::assertSame(1, $code, 'a branch case leak must fail the gate: ' . implode("\n", $out));
            self::assertStringContainsString('fingerprint leak', implode("\n", $out));
        } finally {
            @unlink($tmp);
        }
    }

    public function test_the_ci_gate_flags_a_leak_in_an_arith_eval_response(): void
    {
        // An `arith-eval` rule serves its own `response` on a computed hit — that body never appears
        // at the top level, so the gate must descend into arith-eval.response. This rule's top-level
        // body is clean but the arith-eval response leaks; the gate must flag it.
        $rule = [
            'id' => 'arith-leak-probe',
            'response' => ['headers' => [], 'body' => 'clean top-level body'],
            'behavior' => 'arith-eval',
            'arith-eval' => [
                'left' => 'a',
                'right' => 'b',
                'op' => 'add',
                'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset'],
            ],
        ];
        self::assertSame(1, $this->runGateOn([$rule]));
    }

    public function test_the_ci_gate_flags_a_leak_in_an_iterate_served_shape(): void
    {
        // An `iterate` rule serves the wrap body and the per-sub-call item — nested served shapes the
        // top-level body never carries. A leak planted in wrap.open (and another in item.body) must be
        // caught by the descent.
        $rule = [
            'id' => 'iterate-leak-probe',
            'response' => ['headers' => [], 'body' => 'clean top-level body'],
            'behavior' => 'iterate',
            'iterate' => [
                'parse' => 'xmlrpc-multicall',
                'max_items' => 8,
                'wrap' => ['open' => 'detected via libinjection', 'close' => '</r>'],
                'item' => ['headers' => [], 'body' => 'blocked by ModSecurity'],
            ],
        ];
        self::assertSame(1, $this->runGateOn([$rule]));
    }

    public function test_the_ci_gate_flags_a_leak_in_iterate_response_headers(): void
    {
        // iterate.response.headers is served on the multicall success path (handleIterate renders
        // it), yet it is a nested node the top-level body never carries. A detector signature planted
        // in a served header value (top-level body + wrap + item all kept clean) must be caught by
        // the iterate.response descent — the gap this probe pins closed.
        $rule = [
            'id' => 'iterate-response-header-leak-probe',
            'response' => ['headers' => [], 'body' => 'clean top-level body'],
            'behavior' => 'iterate',
            'iterate' => [
                'parse' => 'xmlrpc-multicall',
                'max_items' => 8,
                'wrap' => ['open' => '<r>', 'close' => '</r>'],
                'item' => ['headers' => [], 'body' => 'clean item body'],
                'response' => ['headers' => ['X-Pingback-Server' => 'mod_security 911100'], 'body' => ''],
            ],
        ];
        self::assertSame(1, $this->runGateOn([$rule]));
    }

    /**
     * Write a rule-set to a scratch artifact and run the CI gate against it via --index; returns the
     * gate's exit code. Nothing lands in the repo.
     *
     * @param array<int,array<string,mixed>> $rules
     */
    private function runGateOn(array $rules): int
    {
        $script = dirname(__DIR__, 2) . '/scripts/ci/check-fingerprint-safety.php';
        $tmp = tempnam(sys_get_temp_dir(), 'fp-behavior-') . '.php';
        file_put_contents($tmp, "<?php\n\nreturn " . var_export($rules, true) . ";\n");
        try {
            exec('php ' . escapeshellarg($script) . ' --index=' . escapeshellarg($tmp) . ' 2>&1', $out, $code);
            self::assertStringContainsString('fingerprint leak', implode("\n", $out), 'gate output: ' . implode("\n", $out));

            return $code;
        } finally {
            @unlink($tmp);
        }
    }
}
