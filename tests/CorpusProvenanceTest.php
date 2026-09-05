<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Corpus provenance: the committed index must be traceable (a pinned upstream commit, a sidecar
 * that verifies it) and a rebuild must never lose coverage silently. The route-key floor is the
 * loud guard — `compile` alone exits 0 while dropping every folded in-repo new-page key, and no
 * other assertion would notice — and it is checked against the fold size so it cannot rot into a
 * no-op as the corpus grows.
 */
final class CorpusProvenanceTest extends TestCase
{
    /**
     * Lower bound on route keys in the committed index. Lower it ONLY in the same commit as a
     * reviewed upstream refresh (`build-corpus --bump`) — that edit is the record of accepted
     * coverage loss — never to make a rebuild pass.
     */
    private const ROUTE_KEY_FLOOR = 5290;

    private const COMPILED = __DIR__ . '/../resources/compiled';
    private const INDEX = self::COMPILED . '/nuclei-index.full.php';
    private const SIDECAR = self::COMPILED . '/manifest.json';

    /** In-repo new-page routes: two from templates/route, one from templates/generated (compile-ai). */
    private const CANARIES = ['GET /.claude.json', 'GET /secrets.json', 'GET /api/tags'];

    /** @var string[] */
    private $cleanup = [];

    protected function setUp(): void
    {
        if (!is_file(self::INDEX) || !is_file(self::SIDECAR)) {
            self::markTestSkipped('compiled index / manifest.json not built');
        }
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->cleanup) as $path) {
            self::rmrf($path);
        }
        $this->cleanup = [];
    }

    // --- the floor -----------------------------------------------------------------------------

    public function test_route_key_count_meets_the_floor(): void
    {
        $count = count(self::index()['routes']);
        self::assertGreaterThanOrEqual(
            self::ROUTE_KEY_FLOOR,
            $count,
            "route keys fell below the floor — a rebuild lost detection coverage (compile without build? off-pin checkout?)"
        );
    }

    public function test_floor_still_catches_a_lost_fold(): void
    {
        // Keys that exist only because merge-routes folded a route-* new-page bundle: exactly the
        // set `compile` alone drops. The floor must sit above that outcome or it guards nothing.
        $index = self::index();
        $foldOnly = 0;
        foreach ($index['routes'] as $entry) {
            $allFolded = true;
            foreach ((array) $entry['b'] as $bundle) {
                if (strncmp((string) ($bundle['pid'] ?? ''), 'route-', 6) !== 0) {
                    $allFolded = false;
                    break;
                }
            }
            if ($allFolded) {
                $foldOnly++;
            }
        }
        $count = count($index['routes']);
        self::assertGreaterThan(0, $foldOnly, 'no fold-only keys: templates/route was not folded at all');
        self::assertLessThan(
            self::ROUTE_KEY_FLOOR,
            $count - $foldOnly,
            sprintf('ROUTE_KEY_FLOOR (%d) no longer catches a lost fold (%d keys, %d fold-only) — raise it', self::ROUTE_KEY_FLOOR, $count, $foldOnly)
        );
    }

    public function test_in_repo_canary_routes_are_folded(): void
    {
        $routes = self::index()['routes'];
        foreach (self::CANARIES as $key) {
            self::assertArrayHasKey($key, $routes, "{$key} missing: templates/route + templates/generated were not folded (run `funnypot build`)");
            $pids = [];
            foreach ((array) $routes[$key]['b'] as $bundle) {
                $pids[] = (string) ($bundle['pid'] ?? '');
            }
            $folded = array_filter($pids, static function (string $pid): bool {
                return strncmp($pid, 'route-', 6) === 0;
            });
            // /api/tags also exists upstream, so presence alone would not prove the fold.
            self::assertNotEmpty($folded, "{$key} routes, but not via a folded route-* bundle: " . implode(',', $pids));
        }
    }

    // --- the sidecar is the readable provenance record ------------------------------------------

    public function test_sidecar_verifies_the_index_and_carries_the_compile_record(): void
    {
        $m = self::sidecar();
        $index = self::index();
        $embedded = $index['manifest'];

        // The pin: a full upstream commit sha, identical in the sidecar and inside the index.
        self::assertMatchesRegularExpression('/^[0-9a-f]{40}$/', (string) $m['upstream_sha'], 'upstream_sha must pin a commit');
        self::assertSame($embedded['upstream_sha'], $m['upstream_sha']);
        self::assertSame($embedded['upstream_tag'], $m['upstream_tag']);
        self::assertSame($embedded['source_tree'], $m['source_tree']);

        // Fingerprint + counts describe the committed bytes.
        self::assertSame(hash_file('sha256', self::INDEX), $m['sha256']);
        self::assertSame(filesize(self::INDEX), $m['artifact_bytes']);
        self::assertSame(count($index['routes']), $m['route_keys']);
        self::assertSame(count($index['templates']), $m['templates_indexed']);

        // Compile record: which compiler, which PHP, when — present even when unknowable.
        foreach (['built_at', 'core_commit', 'php_version'] as $field) {
            self::assertArrayHasKey($field, $m, "manifest.json must carry {$field}");
            self::assertNotSame('', (string) $m[$field]);
        }
        // Field order is the ArtifactWriter / merge-routes contract (either may write the sidecar).
        $keys = array_keys($m);
        $tail = array_slice($keys, (int) array_search('built_at', $keys, true));
        self::assertSame(['built_at', 'core_commit', 'php_version', 'sha256', 'skipped_count', 'artifact_bytes'], $tail);
    }

    // --- doctor --provenance -------------------------------------------------------------------

    public function test_doctor_provenance_passes_on_the_committed_pair(): void
    {
        [$code, $out] = $this->funnypot('doctor --provenance');
        self::assertSame(0, $code, $out);
        self::assertStringContainsString('provenance   : OK', $out);
        self::assertStringContainsString(self::sidecar()['upstream_sha'], $out);
    }

    public function test_doctor_provenance_fails_on_a_tampered_sidecar_or_index(): void
    {
        // A sidecar count that no longer matches the table.
        $dir = $this->copyOfPair();
        $m = self::sidecar();
        $m['route_keys'] = (int) $m['route_keys'] + 1;
        file_put_contents($dir . '/manifest.json', json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        [$code, $out] = $this->funnypot('doctor --provenance --compiled-dir=' . escapeshellarg($dir));
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('route_keys: manifest.json says', $out);

        // One byte flipped in place (same length, inside the header comment): only the sha256
        // can catch it — size and counts still agree.
        $dir = $this->copyOfPair();
        $bytes = (string) file_get_contents($dir . '/nuclei-index.full.php');
        $pos = strpos($bytes, 'DO NOT EDIT');
        self::assertNotFalse($pos);
        $bytes[$pos] = 'd';
        file_put_contents($dir . '/nuclei-index.full.php', $bytes);
        [$code, $out] = $this->funnypot('doctor --provenance --compiled-dir=' . escapeshellarg($dir));
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('sha256: manifest.json says', $out);
        self::assertStringNotContainsString('artifact_bytes: manifest.json says', $out);

        // An unpinned corpus is drift even when the bytes verify.
        $dir = $this->copyOfPair();
        $m = self::sidecar();
        $m['upstream_sha'] = 'unknown';
        file_put_contents($dir . '/manifest.json', json_encode($m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        [$code, $out] = $this->funnypot('doctor --provenance --compiled-dir=' . escapeshellarg($dir));
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('unpinned', $out);
    }

    // --- build-corpus refuses an untraceable or off-pin source ----------------------------------

    public function test_build_corpus_refuses_a_missing_or_unversioned_checkout(): void
    {
        [$code, $out] = $this->funnypot('build-corpus ' . escapeshellarg(sys_get_temp_dir() . '/fp-no-such-checkout-' . getmypid()));
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('checkout not found', $out);

        // Templates without git history (a `nuclei -update-templates` dir) have no recordable
        // revision, so they are refused before anything compiles.
        $dir = $this->tmpDir('nogit');
        mkdir($dir . '/http');
        file_put_contents($dir . '/http/x.yaml', "id: x\n");
        [$code, $out] = $this->funnypot('build-corpus ' . escapeshellarg($dir));
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('not a git checkout', $out);

        // A subdir (or anything without http/) is not a checkout root.
        [$code, $out] = $this->funnypot('build-corpus ' . escapeshellarg($dir . '/http'));
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('checkout ROOT', $out);
    }

    public function test_build_corpus_refuses_an_off_pin_checkout_unless_bumped(): void
    {
        $dir = $this->gitCheckout();
        $pin = (string) self::sidecar()['upstream_sha'];

        [$code, $out] = $this->funnypot('build-corpus ' . escapeshellarg($dir));
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('revision mismatch', $out);
        self::assertStringContainsString($pin, $out);
        self::assertStringContainsString('--bump', $out);

        // --verify never moves the pin, so it is refused the same way.
        [$code, $out] = $this->funnypot('build-corpus --verify ' . escapeshellarg($dir));
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('revision mismatch', $out);

        // The env-var resolution path takes the same gate.
        [$code, $out] = $this->funnypot('build-corpus', ['NUCLEI_TEMPLATES_DIR' => $dir]);
        self::assertSame(2, $code, $out);
        self::assertStringContainsString('revision mismatch', $out);
    }

    // --- helpers -------------------------------------------------------------------------------

    /**
     * A fresh load per call, deliberately NOT cached: a retained copy of the ~6 MB index would sit
     * in process memory for the rest of the suite, on top of the peak a later Rules test hits while
     * tokenizing that same file.
     *
     * @return array<string,mixed>
     */
    private static function index(): array
    {
        return require self::INDEX;
    }

    /** @return array<string,mixed> */
    private static function sidecar(): array
    {
        return (array) json_decode((string) file_get_contents(self::SIDECAR), true);
    }

    /**
     * @param array<string,string> $env
     * @return array{0:int,1:string} exit code + combined output
     */
    private function funnypot(string $args, array $env = []): array
    {
        $cmd = '';
        foreach ($env as $k => $v) {
            $cmd .= $k . '=' . escapeshellarg($v) . ' ';
        }
        $cmd .= 'php -d memory_limit=1G ' . escapeshellarg(__DIR__ . '/../bin/funnypot') . ' ' . $args . ' 2>&1';
        $lines = [];
        $code = 0;
        exec($cmd, $lines, $code);

        return [$code, implode("\n", $lines)];
    }

    private function tmpDir(string $tag): string
    {
        $dir = sys_get_temp_dir() . '/fp-prov-' . $tag . '-' . getmypid() . '-' . uniqid();
        mkdir($dir, 0777, true);
        $this->cleanup[] = $dir;

        return $dir;
    }

    private function copyOfPair(): string
    {
        $dir = $this->tmpDir('pair');
        copy(self::INDEX, $dir . '/nuclei-index.full.php');
        copy(self::SIDECAR, $dir . '/manifest.json');

        return $dir;
    }

    /** A one-commit git repo shaped like a nuclei-templates checkout; its sha can never equal the pin. */
    private function gitCheckout(): string
    {
        $dir = $this->tmpDir('git');
        mkdir($dir . '/http');
        file_put_contents($dir . '/http/x.yaml', "id: x\n");
        $git = 'git -C ' . escapeshellarg($dir) . ' -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false ';
        $lines = [];
        $code = 0;
        exec($git . 'init -q 2>&1 && ' . $git . 'add . 2>&1 && ' . $git . 'commit -q -m x 2>&1', $lines, $code);
        if ($code !== 0) {
            self::markTestSkipped('git unavailable: ' . implode("\n", $lines));
        }

        return $dir;
    }

    private static function rmrf(string $path): void
    {
        if (is_dir($path) && !is_link($path)) {
            foreach (scandir($path) ?: [] as $entry) {
                if ($entry !== '.' && $entry !== '..') {
                    self::rmrf($path . '/' . $entry);
                }
            }
            @rmdir($path);
        } else {
            @unlink($path);
        }
    }
}
