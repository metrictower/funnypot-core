<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * TemplateAttackEmulator::ownsPath() claims a request whenever PathNormalizer::ownershipKey()
 * (any case, any count of trailing slashes) matches a declared owns_path entry. If the rule's own
 * `in: path` match is stricter than that, ownsPath() can be TRUE while matchRule() declines — a
 * silent fallthrough. EmulatorCompiler::ownsPathVariantWarnings() flags this class of bug at
 * compile time; it warns rather than throws (some owns_path rules lean on the runtime
 * Honeypot::hasAuthSuccessWitness backstop instead of full variant coverage), so this drives the
 * warning-collector method directly rather than asserting a build failure.
 */
final class OwnsPathVariantGuardTest extends TestCase
{
    /**
     * @param string[]                       $rawOwns
     * @param array<int,array<string,mixed>> $match
     * @return string[]
     */
    private function warningsFor(array $rawOwns, array $match, string $file = 'owns-variant-test.yaml'): array
    {
        $compiler = new EmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'ownsPathVariantWarnings');
        $method->setAccessible(true);

        return $method->invoke($compiler, $rawOwns, $match, $file);
    }

    public function test_case_sensitive_no_slash_tolerance_path_regex_warns(): void
    {
        $warnings = $this->warningsFor(
            ['/foo'],
            [['in' => 'path', 'regex' => '(?:^|/)foo$', 'ci' => false]]
        );

        self::assertNotEmpty($warnings);
        self::assertStringContainsString("owns_path '/foo'", $warnings[0]);
    }

    public function test_ci_and_slash_tolerant_path_regex_is_clean(): void
    {
        $warnings = $this->warningsFor(
            ['/foo'],
            [['in' => 'path', 'regex' => '(?:^|/)foo/*$', 'ci' => true]]
        );

        self::assertSame([], $warnings);
    }

    public function test_missing_path_condition_warns(): void
    {
        $warnings = $this->warningsFor(
            ['/foo'],
            [['in' => 'method', 'regex' => '^POST$', 'ci' => true]]
        );

        self::assertNotEmpty($warnings);
    }

    public function test_no_in_path_but_in_request_is_clean(): void
    {
        // An `in: request` surface spans the path; such a rule gates on payload, not path form, so the
        // "no in:path" warning must NOT fire (e.g. the WP batch query-alias decoy owns '/' + in:request).
        $warnings = $this->warningsFor(
            ['/'],
            [
                ['in' => 'method', 'regex' => '^POST$', 'ci' => false],
                ['in' => 'request', 'regex' => 'batch/v1.*"requests"', 'dotall' => true, 'ci' => false],
            ]
        );

        self::assertSame([], $warnings);
    }

    public function test_ci_false_but_slash_tolerant_is_clean(): void
    {
        // Explicit ci:false = deliberate case-sensitivity (a device-CVE path a real appliance answers
        // case-sensitively, e.g. FiberHome's /boaform/admin/formLogin). With `/*$` the trailing-slash
        // variants are covered, so no warning — case variants are the author's intended decline.
        $warnings = $this->warningsFor(
            ['/boaform/admin/formLogin'],
            [['in' => 'path', 'regex' => '^/boaform/admin/formLogin/*$', 'ci' => false]]
        );

        self::assertSame([], $warnings);
    }

    public function test_ci_false_without_slash_tolerance_still_warns(): void
    {
        // ci:false does NOT excuse a missing trailing-slash tolerance — the slash variant still warns.
        $warnings = $this->warningsFor(
            ['/boaform/admin/formLogin'],
            [['in' => 'path', 'regex' => '^/boaform/admin/formLogin$', 'ci' => false]]
        );

        self::assertNotEmpty($warnings);
    }

    public function test_wp_xmlrpc_style_regex_is_clean_when_ci_true(): void
    {
        // The 26-wp-xmlrpc.yaml shape: `(?:/|$)` isn't end-anchored, so it already tolerates any
        // count of trailing slashes once `ci: true` covers the case variant.
        $warnings = $this->warningsFor(
            ['/xmlrpc.php'],
            [['in' => 'path', 'regex' => '(?:^|/)xmlrpc\.php(?:/|$)', 'ci' => true]]
        );

        self::assertSame([], $warnings);
    }
}
