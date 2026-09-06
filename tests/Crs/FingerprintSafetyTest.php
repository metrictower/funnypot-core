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
            // Scanner/OAST vocabulary (FP-0262).
            'interactsh oob' => ['oob callback via interactsh'],
            'interact.sh host' => ['<a href="http://interact.sh/x">'],
            'projectdiscovery' => ['see projectdiscovery/nuclei-templates'],
            'oast host' => ['https://abc.oast.fun/x'],
            'oast.me host' => ['Location: https://oast.me'],
            'nuclei word' => ['detected by nuclei'],
            'honeypot word' => ['this is a honeypot'],
            'wafw00f word' => ['wafw00f says cloudflare'],
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
            // The `\b`-bounded scanner-word patterns must not false-positive on prose or on a
            // random generated token (FP-0262): "nucleic" is not the word "nuclei", and a hex
            // digest / base64 run has no word boundary to trip `\bnuclei\b`.
            'nucleic prose' => ['nucleic acid research summary'],
            'nuclei mid-word' => ['panucleitis is a benign finding'],
            'hex digest' => [str_repeat('a1b2c3d4', 4)],
            'base64 run' => ['dGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=='],
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

        // The default set now includes the ~6 MB nuclei index, so run with the same memory the
        // composer/CI invocation uses.
        exec('php -d memory_limit=1G ' . escapeshellarg($script) . ' 2>&1', $out, $code);
        self::assertSame(0, $code, implode("\n", $out));
        self::assertStringContainsString('across 5 artifact(s)', implode("\n", $out), 'all five served artifacts must be scanned');
    }

    public function test_recursive_walk_catches_a_served_leaf_the_old_hand_enumerated_gate_missed(): void
    {
        // Invariant #1 (FP-0262): the gate must be STRICTLY more fail-closed. `expr-eval.response.body`
        // is a served node the old descent-per-shape gate never enumerated, so a signature there
        // escaped it; the recursive walk catches it and names the exact key-path.
        $rule = [
            'id' => 'expr-escape-probe',
            'behavior' => 'expr-eval',
            'response' => ['headers' => [], 'body' => 'clean top-level body'],
            'expr-eval' => [
                'expr' => 'expr', 'bind' => 'result',
                'response' => ['headers' => [], 'body' => 'blocked by OWASP_CRS ruleset 942100'],
            ],
        ];
        self::assertSame(1, $this->runGateOn([$rule]));
    }

    public function test_the_ci_gate_flags_a_leak_in_a_decoy_session_cookie_name(): void
    {
        // decoy-session.cookie_name is served verbatim in Set-Cookie — another node the old gate
        // never descended. A detector signature there must fail the gate.
        $rule = [
            'id' => 'decoy-escape-probe',
            'behavior' => 'decoy-session',
            'response' => ['headers' => [], 'body' => 'clean'],
            'decoy-session' => ['mode' => 'mint', 'cookie_name' => 'libinjection', 'cookie_path' => '/', 'redirect' => '/x'],
        ];
        self::assertSame(1, $this->runGateOn([$rule]));
    }

    public function test_the_ci_gate_fails_closed_on_a_novel_nested_shape(): void
    {
        // A served string under a brand-new shape the skip-list never enumerated must still be
        // scanned (scan-by-default) — the property that stops the next nested shape from escaping.
        $rule = [
            'id' => 'novel',
            'frobnicate' => ['deeply' => ['nested' => ['reply' => ['payload' => 'blocked by OWASP_CRS ruleset']]]],
        ];
        $out = [];
        $code = $this->runGateOnCapturing([$rule], $out);
        self::assertSame(1, $code, implode("\n", $out));
        self::assertStringContainsString('frobnicate.deeply.nested.reply.payload', implode("\n", $out));
    }

    public function test_the_ci_gate_flags_a_leak_in_both_index_bundle_shapes(): void
    {
        // nuclei-index shape: routes[k]['b'][i]['bw'].
        $nuclei = [
            'schema' => 1,
            'manifest' => ['schema' => 1],
            'routes' => ['GET /x' => ['b' => [['pid' => 'p', 't' => ['t'], 'bw' => ['<a href="http://interact.sh/">']]]]],
            'templates' => [],
        ];
        self::assertSame(1, $this->runGateOn($nuclei));

        // flat routes-index shape: routes[k][i]['th'][name][].
        $flat = [
            'routes' => ['GET /y' => [['pid' => 'p', 't' => ['t'], 'th' => ['Location' => ['https://oast.pro']]]]],
            'templates' => [],
        ];
        self::assertSame(1, $this->runGateOn($flat));
    }

    public function test_the_ci_gate_does_not_scan_forbidden_or_matcher_or_key_fields(): void
    {
        // A signature in a NON-served field must NOT trip the gate: forbidden (nf/hf, absent by
        // construction), a matcher/id/tags field, a template-metadata id, or a route KEY. The gate
        // scans served leaves only, so these are clean.
        $nuclei = [
            'schema' => 1,
            'manifest' => ['schema' => 1, 'source' => 'projectdiscovery/nuclei-templates'],
            'routes' => [
                // route KEY carries the token; the bundle serves nothing leaky.
                'GET //interact.sh/en' => ['b' => [['pid' => 'p', 't' => ['nuclei-detect'], 'bw' => ['clean'], 'nf' => ['blocked by ModSecurity']]]],
            ],
            'templates' => ['nuclei-detect' => ['sev' => 'info', 'tags' => ['nuclei'], 'name' => 'a honeypot detector']],
        ];
        self::assertSame(0, $this->runGatePass($nuclei));

        $rule = [
            'id' => 'attack-nuclei-detect',
            'tags' => ['nuclei', 'oast.pro'],
            'match' => [['in' => 'body', 'regex' => 'interactsh', 'contains' => 'oast.me']],
            'response' => ['headers' => [], 'body' => 'clean served body'],
        ];
        self::assertSame(0, $this->runGatePass([$rule]));
    }

    public function test_scan_response_covers_body_and_header_names_and_values(): void
    {
        $guard = $this->guard();
        self::assertNotEmpty($guard->scanResponse('blocked by OWASP_CRS', []));
        self::assertNotEmpty($guard->scanResponse('ok', ['X-Note' => 'detected by nuclei']));
        self::assertNotEmpty($guard->scanResponse('ok', ['Set-Cookie' => ['a=1', 'ModSecurity=2']]));
        self::assertSame([], $guard->scanResponse('clean body', ['Content-Type' => 'text/html']));
    }

    public function test_try_from_package_loads_the_denylist(): void
    {
        self::assertInstanceOf(FingerprintGuard::class, FingerprintGuard::tryFromPackage());
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

    /**
     * Run the gate on a scratch artifact and return its exit code, capturing output for the caller
     * to assert on (no built-in "fingerprint leak" assertion).
     *
     * @param array<int|string,mixed> $artifact
     * @param string[] $out
     */
    private function runGateOnCapturing(array $artifact, array &$out): int
    {
        $script = dirname(__DIR__, 2) . '/scripts/ci/check-fingerprint-safety.php';
        $tmp = tempnam(sys_get_temp_dir(), 'fp-novel-') . '.php';
        file_put_contents($tmp, "<?php\n\nreturn " . var_export($artifact, true) . ";\n");
        try {
            exec('php ' . escapeshellarg($script) . ' --index=' . escapeshellarg($tmp) . ' 2>&1', $out, $code);

            return $code;
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Run the gate on a scratch artifact expected to be CLEAN; assert exit 0 and return it.
     *
     * @param array<int|string,mixed> $artifact
     */
    private function runGatePass(array $artifact): int
    {
        $out = [];
        $code = $this->runGateOnCapturing($artifact, $out);
        self::assertSame(0, $code, 'expected a clean pass but the gate flagged: ' . implode("\n", $out));

        return $code;
    }
}
