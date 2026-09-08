<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Tests\Support\CliProcess;
use PHPUnit\Framework\TestCase;

final class CliAutoloadTest extends TestCase
{
    /** @var string */
    private $dir;

    protected function setUp(): void
    {
        if (!function_exists('proc_open')) {
            self::markTestSkipped('proc_open unavailable');
        }
        $this->dir = sys_get_temp_dir() . '/fp-cli-autoload-' . bin2hex(random_bytes(8));
        mkdir($this->dir, 0700);
        mkdir($this->dir . '/cwd', 0700);
    }

    protected function tearDown(): void
    {
        if (is_string($this->dir)) {
            self::remove($this->dir);
        }
    }

    public function test_development_loader_succeeds_from_unrelated_cwd(): void
    {
        $package = $this->package('checkout');
        $this->loader($package . '/vendor/autoload.php', 'development');
        $this->assertDoctor($package . '/bin/funnypot', 'development');
    }

    /** @dataProvider vendorDirectories */
    public function test_installed_layout_uses_the_host_loader(string $vendor): void
    {
        $package = $this->package('consumer/' . $vendor . '/metrictower/funnypot-core');
        $this->loader(dirname($package, 2) . '/autoload.php', 'host');
        $this->loader($this->dir . '/cwd/vendor/autoload.php', 'wrong-cwd');
        $this->assertDoctor($package . '/bin/funnypot', 'host');
    }

    public static function vendorDirectories(): array
    {
        return [['vendor'], ['custom-dependencies']];
    }

    public function test_package_local_loader_precedes_host_loader(): void
    {
        $package = $this->package('consumer/vendor/metrictower/funnypot-core');
        $this->loader($package . '/vendor/autoload.php', 'development');
        $this->loader(dirname($package, 2) . '/autoload.php', 'wrong-host');
        $this->assertDoctor($package . '/bin/funnypot', 'development');
    }

    public function test_explicit_proxy_precedes_development_and_host_loaders(): void
    {
        $package = $this->package('consumer/vendor/metrictower/funnypot-core');
        $this->loader($package . '/vendor/autoload.php', 'wrong-development');
        $this->loader(dirname($package, 2) . '/autoload.php', 'wrong-host');
        $proxyLoader = $this->dir . '/proxy/autoload.php';
        $this->loader($proxyLoader, 'proxy');
        $this->assertDoctor($this->wrapper($package, $proxyLoader), 'proxy');
    }

    public function test_explicit_proxy_supports_a_nonstandard_package_layout(): void
    {
        $package = $this->package('custom/package-location');
        $proxyLoader = $this->dir . '/proxy/autoload.php';
        $this->loader($proxyLoader, 'proxy');
        $this->assertDoctor($this->wrapper($package, $proxyLoader), 'proxy');
    }

    /** @dataProvider invalidProxyValues */
    public function test_invalid_explicit_proxy_never_falls_back($value): void
    {
        $package = $this->package('consumer/vendor/metrictower/funnypot-core');
        $this->loader($package . '/vendor/autoload.php', 'wrong-development');
        $this->loader(dirname($package, 2) . '/autoload.php', 'wrong-host');
        if ($value === 'missing') { $value = $this->dir . '/missing.php'; }
        if ($value === 'directory') { $value = $this->dir; }
        if ($value === 'uri') { $value = 'file://' . $package . '/vendor/autoload.php'; }
        $this->assertBootstrapFailure($this->wrapper($package, $value));
    }

    public static function invalidProxyValues(): array
    {
        return [[null], [false], [123], [[]], [''], ['missing'], ['directory'], ['uri']];
    }

    /** @dataProvider unsupportedLayouts */
    public function test_missing_or_unsupported_layout_never_searches_cwd_or_ancestors(string $relative): void
    {
        $package = $this->package($relative);
        $this->loader($this->dir . '/cwd/vendor/autoload.php', 'wrong-cwd');
        $this->loader($this->dir . '/autoload.php', 'wrong-ancestor');
        // This would be a plausible two-parent location, but its package suffix is unsupported.
        if (strpos($relative, 'other-vendor') !== false) {
            $this->loader(dirname($package, 2) . '/autoload.php', 'wrong-suffix');
        }
        $this->assertBootstrapFailure($package . '/bin/funnypot');
    }

    public static function unsupportedLayouts(): array
    {
        return [['checkout'], ['consumer/vendor/other-vendor/funnypot-core'], ['consumer/vendor/metrictower/funnypot-core']];
    }

    public function test_loader_execution_failure_does_not_select_a_second_loader(): void
    {
        $package = $this->package('consumer/vendor/metrictower/funnypot-core');
        $this->loader(dirname($package, 2) . '/autoload.php', 'wrong-host');
        $file = $package . '/vendor/autoload.php';
        mkdir(dirname($file), 0700, true);
        file_put_contents($file, "<?php throw new RuntimeException('fixture-failure');\n");
        $this->assertBootstrapFailure($package . '/bin/funnypot');
    }

    public function test_proxy_execution_failure_does_not_select_development_loader(): void
    {
        $package = $this->package('checkout');
        $this->loader($package . '/vendor/autoload.php', 'wrong-development');
        $loader = $this->dir . '/broken-proxy-autoload.php';
        file_put_contents($loader, "<?php throw new RuntimeException('fixture-failure');\n");
        $this->assertBootstrapFailure($this->wrapper($package, $loader));
    }

    private function package(string $relative): string
    {
        $package = $this->dir . '/' . $relative;
        mkdir($package . '/bin', 0700, true);
        copy(__DIR__ . '/../bin/funnypot', $package . '/bin/funnypot');
        mkdir($package . '/resources/compiled', 0700, true);
        $manifest = ['route_keys' => 1, 'templates_indexed' => 1, 'upstream_sha' => str_repeat('a', 40),
            'upstream_tag' => 'fixture', 'source_tree' => 'fixture'];
        $index = ['schema' => 1, 'manifest' => $manifest, 'routes' => ['GET /probe' => ['b' => []]],
            'templates' => ['probe' => ['sev' => 'low']]];
        $bytes = "<?php\nreturn " . var_export($index, true) . ";\n";
        file_put_contents($package . '/resources/compiled/nuclei-index.full.php', $bytes);
        $manifest['sha256'] = hash('sha256', $bytes);
        $manifest['artifact_bytes'] = strlen($bytes);
        file_put_contents($package . '/resources/compiled/manifest.json', json_encode($manifest));
        return $package;
    }

    private function loader(string $path, string $name): void
    {
        if (!is_dir(dirname($path))) { mkdir(dirname($path), 0700, true); }
        file_put_contents($path, '<?php file_put_contents(' . var_export($this->dir . '/loaded', true) . ', '
            . var_export($name . "\n", true) . ', FILE_APPEND);' . "\n");
    }

    private function wrapper(string $package, $value): string
    {
        $path = $this->dir . '/proxy.php';
        file_put_contents($path, '<?php $_composer_autoload_path = ' . var_export($value, true) . '; require '
            . var_export($package . '/bin/funnypot', true) . ';' . "\n");
        return $path;
    }

    private function assertDoctor(string $script, string $loader): void
    {
        [$code, $out, $err] = $this->runFixture($script);
        self::assertSame(0, $code, $out . $err);
        self::assertSame('', $err);
        self::assertStringContainsString('provenance   : OK', $out);
        self::assertSame($loader . "\n", file_get_contents($this->dir . '/loaded'));
    }

    private function assertBootstrapFailure(string $script): void
    {
        [$code, $out, $err] = $this->runFixture($script);
        self::assertSame(2, $code, $out . $err);
        self::assertSame('', $out);
        self::assertNotSame('', $err);
        self::assertStringNotContainsString('Warning:', $err);
        self::assertStringNotContainsString('Stack trace:', $err);
        self::assertFileDoesNotExist($this->dir . '/loaded');
    }

    /** @return array{int,string,string} */
    private function runFixture(string $script): array
    {
        return CliProcess::run([PHP_BINARY, '-d', 'memory_limit=1G', '-d', 'max_execution_time=60', $script,
            'doctor', '--provenance'], $this->dir . '/cwd');
    }

    private static function remove(string $path): void
    {
        if (is_dir($path) && !is_link($path)) {
            foreach (scandir($path) ?: [] as $name) {
                if ($name !== '.' && $name !== '..') { self::remove($path . '/' . $name); }
            }
            rmdir($path);
        } elseif (file_exists($path) || is_link($path)) {
            unlink($path);
        }
    }
}
