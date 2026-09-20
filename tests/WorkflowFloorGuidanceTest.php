<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

final class WorkflowFloorGuidanceTest extends TestCase
{
    public function test_refresh_keeps_floor_and_acceptance_gates_before_pr_creation(): void
    {
        $workflow = Yaml::parseFile(__DIR__ . '/../.github/workflows/update-templates.yml');
        $job = $workflow['jobs']['recompile'];
        $steps = $job['steps'];
        $positions = [];
        foreach ($steps as $i => $step) {
            if (isset($step['name'])) { $positions[$step['name']] = $i; }
        }
        $pr = $positions['Open PR with refreshed index'];
        foreach (['Unit + compiler tests', 'Golden acceptance (real nuclei)', 'License check (upstream must be on the allow-list)',
            'Fingerprint-safety check', 'Runtime fingerprint-safety check (render corpus)'] as $name) {
            self::assertLessThan($pr, $positions[$name], $name);
            self::assertArrayNotHasKey('if', $steps[$positions[$name]], $name);
            self::assertFalse($steps[$positions[$name]]['continue-on-error'] ?? false, $name);
        }
        self::assertFalse($job['continue-on-error'] ?? false);
        self::assertSame('vendor/bin/phpunit', $steps[$positions['Unit + compiler tests']]['run']);
        $body = $steps[$pr]['with']['body'];
        self::assertStringContainsString('below-floor refresh fails before PR creation', $body);
        self::assertStringContainsString('docs/CORPUS-PIPELINE.md#refreshing-the-corpus-moving-the-pin', $body);
        self::assertStringContainsString('requires' . "\n" . 'review, not a floor edit', $body);
        self::assertStringNotContainsString('must be lowered in this PR', $body);
    }
}
