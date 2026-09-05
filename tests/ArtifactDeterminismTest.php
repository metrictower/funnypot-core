<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\ArtifactWriter;
use Funnypot\Core\Compiler\Compiler;
use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * The zero-drift compiled-artifact law (FP-0263): the compile output is a pure function of its
 * inputs. Two compiles of the same inputs produce byte-identical artifacts, the compiled index
 * carries NO wall-clock `built_at` (it moved to the JSON sidecar), and the reproducible
 * `source_tree` provenance stamp takes its place. merge-routes is synchronizing (it removes every
 * owned route-* entry, then folds the current fragment) yet still deterministic: re-folding the
 * committed fragment reproduces the committed index, and the embedded manifest counts + the
 * manifest.json fingerprint stay in step with the index it writes.
 */
final class ArtifactDeterminismTest extends TestCase
{
    private const COMPILED = __DIR__ . '/../resources/compiled';

    /** @var string[] */
    private $cleanup = [];

    protected function tearDown(): void
    {
        foreach ($this->cleanup as $path) {
            if (is_dir($path)) {
                foreach (glob($path . '/*') ?: [] as $f) {
                    @unlink($f);
                }
                @rmdir($path);
            } elseif (is_file($path)) {
                @unlink($path);
            }
        }
        $this->cleanup = [];
    }

    private function tmpDir(string $tag): string
    {
        $dir = sys_get_temp_dir() . '/fp-det-' . $tag . '-' . getmypid() . '-' . uniqid();
        mkdir($dir, 0777, true);
        $this->cleanup[] = $dir;

        return $dir;
    }

    // --- F1: no built_at in the compiled index ---------------------------------------------

    public function test_compiler_drops_built_at_even_when_meta_carries_it(): void
    {
        // A wall-clock built_at in the incoming meta must NOT reach the compiled index manifest —
        // that was the one field that made a recompile never reproduce the committed bytes.
        $empty = $this->tmpDir('corpus');
        $result = (new Compiler())->compile($empty, [
            'tag' => 'v1.2.3',
            'sha' => 'deadbeef',
            'built_at' => '2020-01-01T00:00:00+00:00',
        ]);

        self::assertArrayNotHasKey('built_at', $result['index']['manifest'], 'index manifest must carry no built_at');
        self::assertSame('v1.2.3', $result['index']['manifest']['upstream_tag']);
        self::assertSame('deadbeef', $result['index']['manifest']['upstream_sha']);
    }

    public function test_committed_index_has_no_built_at_and_carries_source_tree(): void
    {
        $file = self::COMPILED . '/nuclei-index.full.php';
        if (!is_file($file)) {
            self::markTestSkipped('nuclei-index.full.php not built');
        }
        $manifest = PhpArrayStore::fromFile($file)->version();
        self::assertArrayNotHasKey('built_at', $manifest, 'committed index must not carry a wall-clock built_at');
        self::assertArrayHasKey('source_tree', $manifest, 'committed index must carry a source_tree provenance stamp');
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', (string) $manifest['source_tree']);
    }

    // --- writer determinism: two writes of one result are byte-identical -------------------

    public function test_two_writes_of_same_result_produce_identical_index_and_sidecar_carries_built_at(): void
    {
        $result = [
            'index' => [
                'schema' => 1,
                'manifest' => [
                    'schema' => 1,
                    'source' => 'test',
                    'upstream_tag' => 't',
                    'upstream_sha' => 's',
                    'templates_in' => 0,
                    'route_keys' => 0,
                ],
                'templates' => [],
                'routes' => [],
            ],
            'manifest' => [
                'schema' => 1,
                'source' => 'test',
                'upstream_tag' => 't',
                'upstream_sha' => 's',
                'templates_in' => 0,
                'route_keys' => 0,
            ],
            'skipped' => [],
        ];

        $a = $this->tmpDir('wa');
        $b = $this->tmpDir('wb');
        (new ArtifactWriter())->write($result, $a . '/nuclei-index.full.php');
        (new ArtifactWriter())->write($result, $b . '/nuclei-index.full.php');

        $idxA = (string) file_get_contents($a . '/nuclei-index.full.php');
        $idxB = (string) file_get_contents($b . '/nuclei-index.full.php');
        self::assertSame($idxA, $idxB, 'two writes of the same result must be byte-identical index files');
        self::assertStringNotContainsString('built_at', $idxA, 'the index file must not contain built_at');

        // The sidecar keeps the wall-clock stamp. Stripped of built_at, the two sidecars are equal
        // (built_at is the ONLY volatile field), which pins that nothing else varies write-to-write.
        $mjA = json_decode((string) file_get_contents($a . '/manifest.json'), true);
        $mjB = json_decode((string) file_get_contents($b . '/manifest.json'), true);
        self::assertArrayHasKey('built_at', $mjA, 'manifest.json sidecar must carry built_at');
        self::assertSame($idxA === '' ? '' : hash('sha256', $idxA), $mjA['sha256'], 'sidecar sha256 must fingerprint the index');
        unset($mjA['built_at'], $mjB['built_at']);
        self::assertSame($mjA, $mjB, 'sidecars must be identical apart from built_at');
    }

    // --- compiler purity: compileDirs twice → identical -----------------------------------

    public function test_emulator_and_route_compilers_are_pure(): void
    {
        $attack = __DIR__ . '/../templates/attack';
        $route = __DIR__ . '/../templates/route';
        if (!is_dir($attack) || !is_dir($route)) {
            self::markTestSkipped('template dirs not present');
        }
        $a1 = (new EmulatorCompiler())->compileDirs([$attack]);
        $a2 = (new EmulatorCompiler())->compileDirs([$attack]);
        self::assertSame($a1, $a2, 'EmulatorCompiler must be a pure function of its inputs');

        $r1 = (new RouteEmulatorCompiler())->compileDirs([$route]);
        $r2 = (new RouteEmulatorCompiler())->compileDirs([$route]);
        self::assertSame($r1, $r2, 'RouteEmulatorCompiler must be a pure function of its inputs');
    }

    // --- merge-routes: idempotent + refreshes counts + refreshes the sidecar fingerprint ---

    public function test_merge_routes_is_idempotent_and_refreshes_counts_and_sidecar(): void
    {
        $index = self::COMPILED . '/nuclei-index.full.php';
        $frag = self::COMPILED . '/funnypot-routes-index.php';
        if (!is_file($index) || !is_file($frag)) {
            self::markTestSkipped('compiled index/fragment not built');
        }
        $bin = escapeshellarg(__DIR__ . '/../bin/funnypot');

        $out1 = $this->tmpDir('m1') . '/nuclei-index.full.php';
        $out2 = $this->tmpDir('m2') . '/nuclei-index.full.php';
        $this->exec("php -d memory_limit=1G {$bin} merge-routes " . escapeshellarg($index) . ' --out=' . escapeshellarg($out1));
        $this->exec("php -d memory_limit=1G {$bin} merge-routes " . escapeshellarg($index) . ' --out=' . escapeshellarg($out2));

        $b1 = (string) file_get_contents($out1);
        $b2 = (string) file_get_contents($out2);
        self::assertSame($b1, $b2, 'two merge-routes runs must be byte-identical (idempotent)');
        // The committed index is itself already a merge-routes output (folds 0), so a re-fold
        // reproduces it byte-for-byte — the double-compile-idempotent guarantee at index level.
        self::assertSame((string) file_get_contents($index), $b1, 'merge-routes must reproduce the committed index byte-for-byte');

        // Embedded manifest counts match the actual index, and no built_at, and source_tree present.
        $folded = require $out1;
        $m = $folded['manifest'];
        self::assertArrayNotHasKey('built_at', $m);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', (string) $m['source_tree']);
        self::assertSame(count($folded['routes']), $m['route_keys'], 'route_keys must equal the actual route count');
        self::assertSame(count($folded['templates']), $m['templates_indexed'], 'templates_indexed must equal the actual template count');

        // The refreshed sidecar's sha256 fingerprints the bytes just written.
        $mj = json_decode((string) file_get_contents(dirname($out1) . '/manifest.json'), true);
        self::assertSame(hash('sha256', $b1), $mj['sha256'], 'sidecar sha256 must fingerprint the folded index');
        self::assertSame(strlen($b1), $mj['artifact_bytes']);
        self::assertSame($m['route_keys'], $mj['route_keys']);
        self::assertSame($m['templates_indexed'], $mj['templates_indexed']);
        self::assertSame($m['source_tree'], $mj['source_tree']);
    }

    // --- synchronizing fold: an empty fragment removes owned entries; the fragment is always written

    public function test_merge_routes_with_an_empty_fragment_removes_owned_entries(): void
    {
        $bin = escapeshellarg(__DIR__ . '/../bin/funnypot');
        $src = $this->tmpDir('mroot');
        $index = [
            'schema' => 1,
            'manifest' => [
                'schema' => 1,
                'source' => 'test',
                'upstream_tag' => 't',
                'upstream_sha' => 's',
                'templates_in' => 0,
                'route_keys' => 2,
                'templates_indexed' => 2,
            ],
            'templates' => ['nuc1' => ['name' => 'nuc1'], 'route-old' => ['name' => 'old']],
            'routes' => [
                'GET /nuc' => ['b' => [['pid' => 'nuc1', 's' => 200, 't' => ['nuc1']]]],
                'GET /owned' => ['b' => [['pid' => 'route-old', 's' => 200, 't' => ['route-old']]]],
            ],
        ];
        file_put_contents($src . '/idx.php', "<?php\n\nreturn " . var_export($index, true) . ";\n");
        file_put_contents($src . '/empty.php', "<?php\n\nreturn " . var_export(['templates' => [], 'routes' => []], true) . ";\n");

        $out = $this->tmpDir('mout') . '/nuclei-index.full.php';
        $this->exec("php -d memory_limit=1G {$bin} merge-routes " . escapeshellarg($src . '/idx.php')
            . ' --fragment=' . escapeshellarg($src . '/empty.php') . ' --out=' . escapeshellarg($out));

        $folded = require $out;
        self::assertArrayNotHasKey('route-old', $folded['templates'], 'owned template must be removed');
        self::assertArrayNotHasKey('GET /owned', $folded['routes'], 'owned-only key must drop');
        self::assertSame($index['routes']['GET /nuc'], $folded['routes']['GET /nuc'], 'the unowned nuclei key is byte-equal');
        self::assertSame(count($folded['routes']), $folded['manifest']['route_keys'], 'route_keys recomputed');
        self::assertSame(count($folded['templates']), $folded['manifest']['templates_indexed'], 'templates_indexed recomputed');
        self::assertSame(1, $folded['manifest']['route_keys']);
    }

    public function test_compile_routes_always_writes_the_fragment_even_when_empty(): void
    {
        $bin = escapeshellarg(__DIR__ . '/../bin/funnypot');
        $empty = $this->tmpDir('croutes');
        $out = $this->tmpDir('crout') . '/funnypot-routes.php';
        $this->exec("php -d memory_limit=1G {$bin} compile-routes " . escapeshellarg($empty) . ' --out=' . escapeshellarg($out));

        $frag = dirname($out) . '/funnypot-routes-index.php';
        self::assertFileExists($frag, 'compile-routes must always write the index fragment (never unlink)');
        self::assertSame(['templates' => [], 'routes' => []], require $frag);
    }

    private function exec(string $cmd): void
    {
        $out = [];
        $code = 0;
        exec($cmd . ' 2>&1', $out, $code);
        self::assertSame(0, $code, "command failed ({$cmd}):\n" . implode("\n", $out));
    }
}
