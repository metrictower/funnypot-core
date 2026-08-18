<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * Smoke-loads the compiled full corpus through the existing PhpArrayStore and asserts a
 * handful of well-known scanner probes route. Skips cleanly when the artifact has not
 * been built (the compiler is a separate, host-only step).
 */
final class CompiledIndexSmokeTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

    protected function setUp(): void
    {
        if (!is_file(self::INDEX)) {
            self::markTestSkipped('nuclei-index.full.php not built — run bin/funnypot compile');
        }
        // The full corpus array is larger than the default CLI limit.
        ini_set('memory_limit', '512M');
    }

    private function inverter(): Honeypot
    {
        return new Honeypot(PhpArrayStore::fromFile(self::INDEX));
    }

    public function test_schema_and_manifest(): void
    {
        $store = PhpArrayStore::fromFile(self::INDEX);
        $manifest = $store->version();
        self::assertSame(1, $manifest['schema']);
        self::assertGreaterThan(1000, $manifest['templates_in']);
        self::assertGreaterThan(1000, $manifest['route_keys']);
    }

    public function test_known_probes_route(): void
    {
        $inv = $this->inverter();

        foreach (['/.git/config', '/.env', '/server-status'] as $path) {
            $d = $inv->detect(new RequestContext('GET', $path));
            self::assertTrue($d->matched, "expected {$path} to route");
            self::assertNotEmpty($d->templateIds());
            self::assertNotSame('', $d->highestSeverity);
        }
    }

    public function test_git_config_routes_to_git_template(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/.git/config'));
        self::assertContains('git-config', $d->templateIds());
    }

    public function test_unknown_path_misses(): void
    {
        $d = $this->inverter()->detect(new RequestContext('GET', '/definitely-not-a-scanner-probe-xyz'));
        self::assertFalse($d->matched);
        self::assertTrue($d->isEmpty());
    }

    public function test_bundles_are_pure_literals(): void
    {
        // No object/closure may survive into the frozen artifact.
        $index = require self::INDEX;
        $sample = array_slice($index['routes'], 0, 50, true);
        array_walk_recursive($sample, static function ($v): void {
            self::assertFalse(is_object($v), 'compiled index must contain no objects');
        });
        self::assertIsArray($index['routes']);
    }
}
