<?php

declare(strict_types=1);

namespace Funnypot\Tests\Laravel;

use PHPUnit\Framework\TestCase;

/**
 * The Laravel bridge (src/Laravel/*) references Illuminate\* classes that are
 * not installed on the host PHP 8.4 pure-unit lane (see CLAUDE.md — Laravel
 * tests need the framework/docker lane). These classes can't be instantiated or
 * autoloaded here (autoloading FunnypotServiceProvider would trigger
 * autoload of \Illuminate\Support\ServiceProvider and fatal). So this suite only
 * asserts static, framework-free facts: the files exist, parse cleanly (bin/
 * verifies php -l separately), and expose the expected shape via reflection on
 * the raw source — never by loading the class.
 */
final class StructuralTest extends TestCase
{
    private const LARAVEL_SRC = __DIR__ . '/../../src/Laravel';

    public function test_expected_bridge_files_exist(): void
    {
        $expected = [
            'FunnypotServiceProvider.php',
            'LaravelRequestMapper.php',
            'LaravelResponseMapper.php',
            'HoneypotMiddleware.php',
            'Console/UpdateTemplatesCommand.php',
        ];

        foreach ($expected as $relative) {
            self::assertFileExists(self::LARAVEL_SRC . '/' . $relative, "missing {$relative}");
        }
    }

    public function test_bridge_files_are_syntactically_valid_php(): void
    {
        foreach ($this->bridgeFiles() as $file) {
            $output = [];
            $exit = 0;
            exec('php -l ' . escapeshellarg($file) . ' 2>&1', $output, $exit);

            self::assertSame(0, $exit, "php -l failed for {$file}:\n" . implode("\n", $output));
        }
    }

    public function test_only_the_laravel_bridge_references_illuminate(): void
    {
        // Framework-agnostic core guarantee (SPEC.md §4): everywhere outside
        // src/Laravel/* must stay Illuminate-free.
        $coreSrc = __DIR__ . '/../../src';
        $offenders = [];

        foreach ($this->phpFilesUnder($coreSrc) as $file) {
            if (strpos($file, self::LARAVEL_SRC) === 0) {
                continue;
            }
            $contents = (string) file_get_contents($file);
            if (stripos($contents, 'Illuminate\\') !== false) {
                $offenders[] = $file;
            }
        }

        self::assertSame([], $offenders, 'Illuminate\\ referenced outside src/Laravel/*: ' . implode(', ', $offenders));
    }

    public function test_illuminate_classes_are_referenced_by_fqcn_not_imported(): void
    {
        // "reference by FQCN without importing" (task constraint): no `use
        // Illuminate\...;` import statement anywhere in the bridge, so a
        // non-Laravel consumer never triggers an Illuminate autoload just by
        // having composer's classmap/psr-4 loader scan these files.
        $offenders = [];

        foreach ($this->bridgeFiles() as $file) {
            $contents = (string) file_get_contents($file);
            if (preg_match('/^use\s+Illuminate\\\\/mi', $contents) === 1) {
                $offenders[] = $file;
            }
        }

        self::assertSame([], $offenders, '`use Illuminate\\...;` import found in: ' . implode(', ', $offenders));
    }

    public function test_service_provider_declares_register_boot_and_provides(): void
    {
        $contents = (string) file_get_contents(self::LARAVEL_SRC . '/FunnypotServiceProvider.php');

        foreach (['function register(): void', 'function boot(): void', 'function provides(): array'] as $needle) {
            self::assertStringContainsString($needle, $contents);
        }
        self::assertStringContainsString('extends \\Illuminate\\Support\\ServiceProvider', $contents);
        self::assertStringContainsString("mergeConfigFrom(__DIR__ . '/../../config/funnypot.php', 'funnypot')", $contents);
    }

    public function test_update_command_declares_the_artisan_signature(): void
    {
        $contents = (string) file_get_contents(self::LARAVEL_SRC . '/Console/UpdateTemplatesCommand.php');

        self::assertStringContainsString('funnypot:update', $contents);
        self::assertStringContainsString('extends \\Illuminate\\Console\\Command', $contents);
    }

    public function test_composer_json_declares_auto_discovery_and_keeps_illuminate_out_of_require(): void
    {
        $composer = json_decode((string) file_get_contents(__DIR__ . '/../../composer.json'), true);

        self::assertSame(
            ['Funnypot\\Laravel\\FunnypotServiceProvider'],
            $composer['extra']['laravel']['providers'] ?? null
        );

        foreach (array_keys($composer['require'] ?? []) as $package) {
            self::assertStringNotContainsStringIgnoringCase('illuminate/', $package);
        }
    }

    public function test_config_file_declares_the_documented_knobs(): void
    {
        // Can't require() this on the pure-unit lane: its default 'mode' and
        // 'seed_salt' values call Laravel's env() helper directly (not inside a
        // closure), which doesn't exist without the framework booted. So this
        // checks shape/defaults statically instead of executing the file.
        $configPath = __DIR__ . '/../../config/funnypot.php';
        $contents = (string) file_get_contents($configPath);

        self::assertStringContainsString('declare(strict_types=1);', $contents);

        foreach ([
            'mode', 'gate', 'path_scope', 'persona_seed', 'persona_breadth',
            'response_style', 'severity_ceiling', 'max_body_bytes', 'latency_ms',
            'trusted_bypass', 'kill_switch', 'probe_signature', 'seed_salt', 'exclude',
        ] as $key) {
            self::assertMatchesRegularExpression("/'{$key}'\\s*=>/", $contents, "config missing '{$key}'");
        }

        self::assertMatchesRegularExpression(
            "/'mode'\\s*=>\\s*env\\('NUCLEI_INVERTER_MODE',\\s*'detect'\\)/",
            $contents,
            'default mode must stay inert (detect)'
        );
        self::assertMatchesRegularExpression("/'gate'\\s*=>\\s*null,/", $contents, 'default gate must stay closed');
    }

    /** @return string[] */
    private function bridgeFiles(): array
    {
        return $this->phpFilesUnder(self::LARAVEL_SRC);
    }

    /** @return string[] */
    private function phpFilesUnder(string $dir): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS));
        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        sort($files);

        return $files;
    }
}
