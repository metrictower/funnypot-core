<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Crs\FingerprintGuard;
use Funnypot\RequestContext;
use Funnypot\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The request-aware Laravel Ignition execute-solution rule (CVE-2021-3129, attack rule 92). Drives
 * the compiled attack rules against a live RequestContext, pinning the zero-execution dispatch and
 * its safety invariants: the ONLY body read is the first posted `solution` class leaf, every case
 * returns a canned JSON string (parameters.viewFile / variableName are never read — no file, no
 * eval, no egress), reflection is JSON- and denylist-safe, and the position-blind port degrades to
 * the base response.
 *
 * NOTE ON PATHS: /_ignition/execute-solution has no route key, so a POST misses the exact store and
 * reaches the attack tier. A GET falls back to the same path's (absent) GET bundle and then to 404,
 * so a GET must never dispatch here.
 */
final class IgnitionExecuteSolutionTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';
    private const PATH = '/_ignition/execute-solution';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::COMPILED);
    }

    /** A full CVE-2021-3129 payload with a real namespaced solution class + the RCE parameters. */
    private function cvePayload(string $leaf, string $viewFile = 'phar://tmp/exploit.phar/x'): string
    {
        // Valid JSON: PHP namespace separators are escaped (\\). The parameters are the RCE vector
        // a real exploit sends; the rule must ignore them entirely.
        return '{"solution":"Facade\\\\Ignition\\\\Solutions\\\\' . $leaf
            . '","parameters":{"variableName":"cmd","viewFile":"' . $viewFile . '"}}';
    }

    private function serve(string $method, ?string $body): ?object
    {
        return $this->emulator()->emulate(new RequestContext($method, self::PATH, '', [], $body));
    }

    /** The compiled Ignition rule in isolation, so a gate/parameter test is not shadowed by another
     *  attack rule (e.g. an LFI rule that matches a `/etc/passwd` viewFile before priority 92). */
    private function isolatedRule(): array
    {
        foreach ((require self::COMPILED) as $rule) {
            if (($rule['id'] ?? '') === 'attack-ignition-execute-solution') {
                return $rule;
            }
        }
        self::fail('attack-ignition-execute-solution not compiled');
    }

    private function isolated(): TemplateAttackEmulator
    {
        return new TemplateAttackEmulator([$this->isolatedRule()]);
    }

    /** Decode a served JSON body's `message` field (the raw body carries JSON-escaped quotes). */
    private function message(object $resp): string
    {
        $decoded = json_decode($resp->body, true);
        self::assertIsArray($decoded, 'body must be valid JSON: ' . $resp->body);

        return (string) ($decoded['message'] ?? '');
    }

    // --- compile / ordering -----------------------------------------------------------------

    public function test_rule_compiled_unique_and_zero_execution_shaped(): void
    {
        $rules = require self::COMPILED;
        $ids = array_map(static function (array $r): string {
            return (string) $r['id'];
        }, $rules);
        self::assertContains('attack-ignition-execute-solution', $ids);
        self::assertSame(1, array_count_values($ids)['attack-ignition-execute-solution'], 'rule id must be unique');

        $rule = null;
        foreach ($rules as $r) {
            if (($r['id'] ?? '') === 'attack-ignition-execute-solution') {
                $rule = $r;
            }
        }
        self::assertNotNull($rule);
        // The dispatch is a `branch` — the only-ever-render-one-authored-response primitive. No code
        // primitive is present; the sole body read is one capture-condition.
        self::assertSame('branch', $rule['behavior'] ?? null, 'must dispatch via branch (canned responses only)');
        self::assertArrayNotHasKey('arith-eval', $rule);
        self::assertArrayNotHasKey('iterate', $rule);
    }

    // --- request-aware dispatch (each solution -> its canned JSON) ---------------------------

    /**
     * @dataProvider solutions
     */
    public function test_each_solution_dispatches_to_its_canned_json(string $leaf, string $needle): void
    {
        foreach ([$this->cvePayload($leaf), '{"solution":"' . $leaf . '"}'] as $body) {
            $resp = $this->serve('POST', $body);
            self::assertNotNull($resp, "{$leaf} must dispatch");
            self::assertSame(200, $resp->status, "{$leaf} status");
            self::assertSame('application/json', $resp->headers['Content-Type'] ?? null, "{$leaf} Content-Type");
            self::assertStringContainsString($needle, $resp->body, "{$leaf} must return its canned body");
            self::assertIsArray(json_decode($resp->body, true), "{$leaf} body must be valid JSON: " . $resp->body);
        }
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function solutions(): array
    {
        return [
            'CVE MakeView'        => ['MakeViewVariableOptionalSolution', 'The parameters passed to the solution are invalid.'],
            'GenerateAppKey'      => ['GenerateAppKeySolution', '{"success":true}'],
            'RunMigrations'       => ['RunMigrationsSolution', '{"success":true}'],
            'unknown class'       => ['SomeUnknownSolution', 'not found'],
        ];
    }

    public function test_unknown_solution_reflects_only_the_bounded_leaf(): void
    {
        // The base (unknown-solution) response reflects the captured leaf; the capture is bounded to a
        // letter-initial PHP-class token, so the reflection is XML/JSON-inert.
        $resp = $this->serve('POST', '{"solution":"TotallyMadeUpSolution"}');
        self::assertNotNull($resp);
        self::assertSame('Solution "TotallyMadeUpSolution" not found.', $this->message($resp));
    }

    public function test_first_solution_wins_a_planted_second_cannot_steer(): void
    {
        // Mirrors the xmlrpc match.1 discipline: dispatch keys on the FIRST captured solution only, so
        // a planted second "solution" cannot redirect it to a different case.
        $body = '{"solution":"MakeViewVariableOptionalSolution","note":"solution","also":"\"solution\":\"RunMigrationsSolution\""}';
        $resp = $this->serve('POST', $body);
        self::assertNotNull($resp);
        self::assertStringContainsString('The parameters passed to the solution are invalid.', $resp->body);
        self::assertStringNotContainsString('success', $resp->body, 'the planted second solution must not steer the dispatch');
    }

    public function test_parameters_are_never_read_zero_execution(): void
    {
        // Same solution, wildly different RCE parameters (viewFile / variableName) — the response is
        // byte-identical. parameters.viewFile is NEVER read: no file, no include, no eval, no egress.
        // Isolated to this one rule so an LFI/traversal payload in viewFile can't trip another rule.
        $emu = $this->isolated();
        $post = function (string $viewFile) use ($emu) {
            return $emu->emulate(new RequestContext('POST', self::PATH, '', [], $this->cvePayload('MakeViewVariableOptionalSolution', $viewFile)));
        };
        $a = $post('phar://a/evil.phar/x');
        $b = $post('/etc/passwd');
        $c = $post('http://attacker.example/x');
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertNotNull($c);
        self::assertSame($a->body, $b->body, 'the posted viewFile must not change the response');
        self::assertSame($a->body, $c->body, 'a URL viewFile must not change the response (no egress)');
    }

    public function test_reflected_leaf_is_denylist_and_json_safe(): void
    {
        // Adversarial leaves that try to smuggle the denied \b9\d{5}\b run reflect safely: the
        // letter-initial capture can never begin a bare 6-digit-9 token, and the value stays inside a
        // JSON string.
        $guard = FingerprintGuard::fromPackage();
        foreach (['Foo900000', 'A999999', 'Sol_900000tail', 'Zzz912345end'] as $leaf) {
            $resp = $this->serve('POST', '{"solution":"' . $leaf . '"}');
            self::assertNotNull($resp, "leaf {$leaf} must dispatch");
            self::assertSame([], $guard->scan($resp->body), "leaf {$leaf} must not leak a denied token: " . $resp->body);
            self::assertIsArray(json_decode($resp->body, true), "leaf {$leaf} must stay valid JSON: " . $resp->body);
        }
    }

    // --- method gate + non-dispatch cases ---------------------------------------------------

    public function test_get_never_dispatches(): void
    {
        // Gated to POST: a GET (even with a solution body) must not dispatch THIS rule. Isolated so
        // the assertion is about the Ignition rule's own method gate, not the global attack gauntlet.
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('GET', self::PATH, '', [], $this->cvePayload('MakeViewVariableOptionalSolution'))));
    }

    public function test_solutionless_post_does_not_dispatch(): void
    {
        // No "solution" key => the capture condition fails => the rule does not match => 404 territory,
        // never a synthetic 500 (only-upgrade-a-404). Isolated to this rule.
        $emu = $this->isolated();
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '{"parameters":{"viewFile":"x"}}')));
        self::assertNull($emu->emulate(new RequestContext('POST', self::PATH, '', [], '')));
    }

    // --- position-blind port degradation ----------------------------------------------------

    public function test_position_blind_port_degrades_to_base(): void
    {
        // The rule matched during classify (a request present), capturing the solution. On the
        // position-blind port (renderRule with $r === null) no branch case can evaluate, so the base
        // response serves — the safe degradation, still reflecting the captured leaf, no crash, no
        // execution.
        $port = $this->emulator()->renderRule($this->isolatedRule(), ['solution' => 'MakeViewVariableOptionalSolution'], 0, null);
        self::assertNotNull($port);
        self::assertSame('Solution "MakeViewVariableOptionalSolution" not found.', $this->message($port), 'the port must serve the base response, not a branch case');
        self::assertStringNotContainsString('parameters passed to the solution', $port->body, 'the MakeView case must NOT fire on the port');
        self::assertSame([], FingerprintGuard::fromPackage()->scan($port->body));
    }
}
