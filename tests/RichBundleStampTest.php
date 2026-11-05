<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RichBundleStamp;
use Funnypot\Core\Response\RouteTemplateSet;
use PHPUnit\Framework\TestCase;

/**
 * The build stamps mixed GET route entries with the indices of their rich-renderable bundles.
 */
final class RichBundleStampTest extends TestCase
{
    /** @return array<string,mixed> */
    private static function bundle(string $pid, string $id, bool $bin = false): array
    {
        $b = ['pid' => $pid, 's' => 200, 't' => [$id], 'bw' => [], 'hw' => []];
        if ($bin) {
            $b['bin'] = 'AA==';
        }

        return $b;
    }

    private static function routes(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    /** @return array<string,mixed> */
    private static function index(): array
    {
        $login = self::bundle('wordpress', 'wordpress-login');
        $stub = self::bundle('fixture', 'fixture-stub');

        return ['schema' => 1, 'manifest' => [], 'templates' => [], 'routes' => [
            'GET /wp-login.php' => ['b' => [$stub, $login, $stub]],
            'GET /all-rich' => ['b' => [self::bundle('fixture', 'fixture-icon', true)]],
            'GET /bait-only' => ['b' => [$stub, $stub]],
            'GET /' => ['b' => [$stub, $login]],
            'POST /wp-login.php' => ['b' => [$stub, $login]],
            'GET /stale' => ['b' => [$stub, $stub], RichBundleStamp::KEY => [0]],
        ]];
    }

    public function test_stamps_only_mixed_get_keys(): void
    {
        $out = (new RichBundleStamp())->apply(self::index(), self::routes());
        $routes = $out['index']['routes'];

        self::assertSame([1], $routes['GET /wp-login.php'][RichBundleStamp::KEY]);
        self::assertSame(1, $out['stamped']);
        foreach (['GET /all-rich', 'GET /bait-only', 'GET /', 'POST /wp-login.php', 'GET /stale'] as $key) {
            self::assertArrayNotHasKey(RichBundleStamp::KEY, $routes[$key], $key);
        }
    }

    public function test_apply_is_idempotent_and_strips_stale_stamps(): void
    {
        $stamp = new RichBundleStamp();
        $once = $stamp->apply(self::index(), self::routes())['index'];
        $twice = $stamp->apply($once, self::routes())['index'];

        self::assertSame($once, $twice);
        self::assertArrayNotHasKey(RichBundleStamp::KEY, $once['routes']['GET /stale']);
    }

    public function test_committed_index_equals_a_fresh_non_empty_stamp(): void
    {
        $committed = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        $fresh = (new RichBundleStamp())->apply($committed, self::routes());

        self::assertSame($committed['routes'], $fresh['index']['routes'], 'the committed index carries the current stamp');
        self::assertGreaterThanOrEqual(50, $fresh['stamped']);
    }

    public function test_merge_routes_fails_without_route_rules(): void
    {
        $dir = sys_get_temp_dir() . '/fp-rbs-' . bin2hex(random_bytes(4));
        mkdir($dir);
        $index = ['schema' => 1, 'manifest' => [], 'templates' => [], 'routes' => []];
        file_put_contents($dir . '/idx.php', "<?php\n\nreturn " . var_export($index, true) . ";\n");
        file_put_contents($dir . '/frag.php', "<?php\n\nreturn " . var_export(['templates' => [], 'routes' => []], true) . ";\n");
        $bin = escapeshellarg(__DIR__ . '/../bin/funnypot');
        $base = "php -d memory_limit=1G {$bin} merge-routes " . escapeshellarg($dir . '/idx.php')
            . ' --fragment=' . escapeshellarg($dir . '/frag.php') . ' --out=' . escapeshellarg($dir . '/out.php');

        try {
            $code = 0;
            $out = [];
            exec($base . ' 2>&1', $out, $code);
            self::assertSame(2, $code, 'a missing routes file must fail: ' . implode("\n", $out));
            self::assertStringContainsString('route rules', implode("\n", $out));

            file_put_contents($dir . '/funnypot-routes.php', "<?php\n\nreturn [];\n");
            $out = [];
            exec($base . ' 2>&1', $out, $code);
            self::assertSame(2, $code, 'an empty routes file must fail');
            self::assertStringContainsString('route rules', implode("\n", $out));
            self::assertFileDoesNotExist($dir . '/out.php');

            copy(__DIR__ . '/../resources/compiled/funnypot-routes.php', $dir . '/funnypot-routes.php');
            $out = [];
            exec($base . ' 2>&1', $out, $code);
            self::assertSame(0, $code, 'with the routes file beside the fragment merge-routes succeeds: ' . implode("\n", $out));
            self::assertFileExists($dir . '/out.php');
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }
}
