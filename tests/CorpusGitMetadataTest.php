<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The nuclei CLI's display provenance is a pure function of the source commit. Git's configured
 * abbreviation length and locally available tags must not change compile or verify bytes. The
 * fixture runs an unmodified copy of the real CLI from an isolated package root, while a test-only
 * autoload shim supplies the actual installed compiler classes.
 */
final class CorpusGitMetadataTest extends TestCase
{
    private const COMMIT_DATE = '2024-02-03T04:05:06+00:00';

    /** @var string[] */
    private $cleanup = [];

    /** @var string */
    private $package = '';

    /** @var string */
    private $source = '';

    /** @var string */
    private $sha = '';

    protected function setUp(): void
    {
        $this->package = $this->tmpDir('package');
        $this->source = $this->tmpDir('source');
        $this->stagePackage();
        $this->stageNucleiSource();
    }

    protected function tearDown(): void
    {
        foreach (array_reverse($this->cleanup) as $path) {
            self::rmrf($path);
        }
        $this->cleanup = [];
    }

    public function test_compile_uses_full_sha_independent_of_abbrev_and_tags(): void
    {
        $runs = [];
        $this->git('config core.abbrev 7');
        $runs[] = $this->compileTo('plain-7');

        $this->git('config core.abbrev 11');
        $runs[] = $this->compileTo('plain-11');

        $this->git('tag fixture-release');
        $this->git('config core.abbrev 7');
        $runs[] = $this->compileTo('tagged-7');

        $this->git('config core.abbrev 11');
        $runs[] = $this->compileTo('tagged-11');

        $expectedIndex = $runs[0]['bytes'];
        $expectedSidecar = $runs[0]['sidecar'];
        self::assertGreaterThan(0, count($runs[0]['index']['routes']), 'the tiny corpus must compile at least one route');
        foreach ($runs as $run) {
            self::assertSame($this->sha, $run['index']['manifest']['upstream_tag']);
            self::assertSame($this->sha, $run['index']['manifest']['upstream_sha']);
            self::assertSame($this->sha, $run['sidecar']['upstream_tag']);
            self::assertSame($this->sha, $run['sidecar']['upstream_sha']);
            self::assertSame(hash('sha256', $run['bytes']), $run['sidecar']['sha256']);
            self::assertSame(strlen($run['bytes']), $run['sidecar']['artifact_bytes']);
            self::assertSame($expectedIndex, $run['bytes'], 'Git refs/config must not change compiled index bytes');
            self::assertSame($expectedSidecar, $run['sidecar'], 'Git refs/config must not change sidecar metadata');
        }
    }

    public function test_verify_is_hermetic_but_still_compares_every_index_byte(): void
    {
        $this->git('config core.abbrev 7');
        $this->runCli('compile ' . escapeshellarg($this->source . '/http')
            . ' --out=' . escapeshellarg($this->package . '/resources/compiled/nuclei-index.full.php'));
        $this->runCli('merge-routes --fragment=' . escapeshellarg($this->package . '/resources/compiled/funnypot-routes-index.php'));
        $originalIndex = (string) file_get_contents($this->package . '/resources/compiled/nuclei-index.full.php');
        $originalSidecar = (string) file_get_contents($this->package . '/resources/compiled/manifest.json');
        $originalParsed = require $this->package . '/resources/compiled/nuclei-index.full.php';

        foreach ([7, 11] as $abbrev) {
            $this->git('config core.abbrev ' . $abbrev);
            [$code, $output] = $this->runCli('build-corpus --verify ' . escapeshellarg($this->source), false);
            self::assertSame(0, $code, $output);
            $this->assertPairUnchanged($originalIndex, $originalSidecar);
        }

        $this->git('tag fixture-release');
        foreach ([7, 11] as $abbrev) {
            $this->git('config core.abbrev ' . $abbrev);
            [$code, $output] = $this->runCli('build-corpus --verify ' . escapeshellarg($this->source), false);
            self::assertSame(0, $code, $output);
            $this->assertPairUnchanged($originalIndex, $originalSidecar);
        }

        $routeTamper = $this->replaceOnce($originalIndex, "'s' => 200", "'s' => 201");
        file_put_contents($this->package . '/resources/compiled/nuclei-index.full.php', $routeTamper);
        $routeTamperedIndex = require $this->package . '/resources/compiled/nuclei-index.full.php';
        self::assertSame($originalParsed['manifest'], $routeTamperedIndex['manifest'], 'route tamper must leave metadata unchanged');
        self::assertSame(201, $routeTamperedIndex['routes']['GET /fixture-status']['b'][0]['s']);
        [$code, $output] = $this->runCli('build-corpus --verify ' . escapeshellarg($this->source), false);
        self::assertSame(1, $code, $output);
        $this->assertFixtureMismatchScratch($output);

        file_put_contents($this->package . '/resources/compiled/nuclei-index.full.php', $originalIndex);
        $tagField = "'upstream_tag' => '" . $this->sha . "'";
        $tagTamper = $this->replaceOnce(
            $originalIndex,
            $tagField,
            "'upstream_tag' => '" . str_repeat('f', 40) . "'"
        );
        file_put_contents($this->package . '/resources/compiled/nuclei-index.full.php', $tagTamper);
        $tamperedIndex = require $this->package . '/resources/compiled/nuclei-index.full.php';
        self::assertSame($this->sha, $tamperedIndex['manifest']['upstream_sha'], 'tag-only tamper must leave the pin unchanged');
        self::assertNotSame($this->sha, $tamperedIndex['manifest']['upstream_tag']);
        [$code, $output] = $this->runCli('build-corpus --verify ' . escapeshellarg($this->source), false);
        self::assertSame(1, $code, $output);
        $this->assertFixtureMismatchScratch($output);

        file_put_contents($this->package . '/resources/compiled/nuclei-index.full.php', $originalIndex);
        file_put_contents($this->package . '/resources/compiled/manifest.json', $originalSidecar);
        $this->assertPairUnchanged($originalIndex, $originalSidecar);
    }

    public function test_verify_refuses_off_pin_and_unversioned_sources_without_writes(): void
    {
        $this->runCli('compile ' . escapeshellarg($this->source . '/http')
            . ' --out=' . escapeshellarg($this->package . '/resources/compiled/nuclei-index.full.php'));
        $this->runCli('merge-routes --fragment=' . escapeshellarg($this->package . '/resources/compiled/funnypot-routes-index.php'));
        $originalIndex = (string) file_get_contents($this->package . '/resources/compiled/nuclei-index.full.php');
        $originalSidecar = (string) file_get_contents($this->package . '/resources/compiled/manifest.json');

        file_put_contents($this->source . '/revision.txt', "second revision\n");
        $this->git('add revision.txt');
        $this->gitCommit('second revision');
        foreach (['--verify', '--verify --bump'] as $flags) {
            [$code, $output] = $this->runCli('build-corpus ' . $flags . ' ' . escapeshellarg($this->source), false);
            self::assertSame(2, $code, $output);
            self::assertStringContainsString('revision mismatch', $output);
            $this->assertPairUnchanged($originalIndex, $originalSidecar);
        }

        $unversioned = $this->tmpDir('unversioned');
        mkdir($unversioned . '/http', 0777, true);
        copy($this->source . '/http/fixture.yaml', $unversioned . '/http/fixture.yaml');
        [$code, $output] = $this->runCli('build-corpus --verify ' . escapeshellarg($unversioned), false);
        self::assertSame(2, $code, $output);
        self::assertStringContainsString('not a git checkout', $output);
        $this->assertPairUnchanged($originalIndex, $originalSidecar);
    }

    public function test_compile_crs_keeps_git_describe_tag_and_writes_only_inside_fixture(): void
    {
        $crs = $this->tmpDir('crs');
        mkdir($crs . '/rules', 0777, true);
        copy(__DIR__ . '/fixtures/crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf', $crs . '/rules/xss.conf');
        $this->initGit($crs);
        $this->gitIn($crs, 'tag crs-fixture-release');
        $crsSha = $this->gitIn($crs, 'rev-parse HEAD');

        $out = $this->package . '/templates/attack-crs';
        $this->runCli('compile-crs ' . escapeshellarg($crs . '/rules') . ' --out=' . escapeshellarg($out));
        $manifestPath = $this->package . '/resources/compiled/crs-manifest.json';
        $manifest = json_decode((string) file_get_contents($manifestPath), true);
        self::assertSame('crs-fixture-release', $manifest['tag']);
        self::assertSame($crsSha, $manifest['sha']);
        self::assertNotEmpty(glob($out . '/*.yaml') ?: [], 'the CRS fixture must compile at least one class template');
        self::assertStringStartsWith($this->package . '/', $manifestPath);
    }

    private function stagePackage(): void
    {
        foreach (['bin', 'vendor', 'resources/compiled', 'templates/route', 'templates/generated', 'tmp'] as $dir) {
            mkdir($this->package . '/' . $dir, 0777, true);
        }
        copy(__DIR__ . '/../bin/funnypot', $this->package . '/bin/funnypot');
        $autoload = realpath(__DIR__ . '/../vendor/autoload.php');
        self::assertNotFalse($autoload, 'the CLI fixture needs the package vendor autoloader');
        file_put_contents(
            $this->package . '/vendor/autoload.php',
            "<?php\n\nrequire " . var_export($autoload, true) . ";\n"
        );
        file_put_contents(
            $this->package . '/resources/compiled/funnypot-routes-index.php',
            "<?php\n\ndeclare(strict_types=1);\n\nreturn ['templates' => [], 'routes' => []];\n"
        );
    }

    private function stageNucleiSource(): void
    {
        mkdir($this->source . '/http', 0777, true);
        file_put_contents($this->source . '/http/fixture.yaml', <<<'YAML'
id: fixture-status
info:
  name: Fixture status page
  severity: medium
  tags: fixture
http:
  - method: GET
    path:
      - "{{BaseURL}}/fixture-status"
    matchers:
      - type: status
        status:
          - 200
YAML
        );
        $this->initGit($this->source);
        $this->sha = $this->git('rev-parse HEAD');
    }

    private function initGit(string $dir): void
    {
        $this->gitIn($dir, 'init -q --template=');
        mkdir($dir . '/.git/no-hooks');
        $this->gitIn($dir, 'config core.hooksPath ' . escapeshellarg($dir . '/.git/no-hooks'));
        $this->gitIn($dir, 'config user.name fixture');
        $this->gitIn($dir, 'config user.email fixture@example.invalid');
        $this->gitIn($dir, 'config commit.gpgsign false');
        $this->gitIn($dir, 'config tag.gpgSign false');
        $this->gitIn($dir, 'add .');
        $this->gitCommitIn($dir, 'fixture');
    }

    /** @return array{bytes:string,index:array<string,mixed>,sidecar:array<string,mixed>} */
    private function compileTo(string $name): array
    {
        $dir = $this->package . '/runs/' . $name;
        mkdir($dir, 0777, true);
        $path = $dir . '/nuclei-index.full.php';
        $this->runCli('compile ' . escapeshellarg($this->source . '/http') . ' --out=' . escapeshellarg($path));
        $bytes = (string) file_get_contents($path);

        return [
            'bytes' => $bytes,
            'index' => require $path,
            'sidecar' => (array) json_decode((string) file_get_contents($dir . '/manifest.json'), true),
        ];
    }

    /** @return array{0:int,1:string} */
    private function runCli(string $args, bool $mustPass = true): array
    {
        $command = 'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 '
            . 'SOURCE_DATE_EPOCH=1706933106 TMPDIR=' . escapeshellarg($this->package . '/tmp') . ' '
            . escapeshellarg(PHP_BINARY)
            . ' -d memory_limit=512M ' . escapeshellarg($this->package . '/bin/funnypot')
            . ' ' . $args . ' 2>&1';
        $lines = [];
        $code = 0;
        exec($command, $lines, $code);
        $output = implode("\n", $lines);
        if ($mustPass) {
            self::assertSame(0, $code, $output);
        }

        return [$code, $output];
    }

    private function assertFixtureMismatchScratch(string $output): void
    {
        self::assertStringContainsString('MISMATCH', $output);
        self::assertMatchesRegularExpression(
            '~rebuilt copy kept at '
                . preg_quote($this->package . '/tmp/fp-verify-', '~')
                . '[0-9]+/folded/nuclei-index\.full\.php~',
            $output,
            'an intentional mismatch must retain scratch only below the fixture package'
        );
    }

    private function git(string $args): string
    {
        return $this->gitIn($this->source, $args);
    }

    private function gitCommit(string $message): void
    {
        $this->gitCommitIn($this->source, $message);
    }

    private function gitCommitIn(string $dir, string $message): void
    {
        $prefix = 'GIT_AUTHOR_DATE=' . escapeshellarg(self::COMMIT_DATE)
            . ' GIT_COMMITTER_DATE=' . escapeshellarg(self::COMMIT_DATE) . ' ';
        $this->gitIn($dir, 'commit -q -m ' . escapeshellarg($message), $prefix);
    }

    private function gitIn(string $dir, string $args, string $prefix = ''): string
    {
        $command = 'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 ' . $prefix
            . 'git -C ' . escapeshellarg($dir) . ' ' . $args . ' 2>&1';
        $lines = [];
        $code = 0;
        exec($command, $lines, $code);
        self::assertSame(0, $code, implode("\n", $lines));

        return trim(implode("\n", $lines));
    }

    private function assertPairUnchanged(string $index, string $sidecar): void
    {
        self::assertSame($index, (string) file_get_contents($this->package . '/resources/compiled/nuclei-index.full.php'));
        self::assertSame($sidecar, (string) file_get_contents($this->package . '/resources/compiled/manifest.json'));
    }

    private function replaceOnce(string $bytes, string $from, string $to): string
    {
        $position = strpos($bytes, $from);
        self::assertNotFalse($position, "fixture bytes do not contain {$from}");

        return substr_replace($bytes, $to, (int) $position, strlen($from));
    }

    private function tmpDir(string $tag): string
    {
        $dir = sys_get_temp_dir() . '/fp-git-meta-' . $tag . '-' . getmypid() . '-' . uniqid();
        self::assertTrue(mkdir($dir, 0777, true), "cannot create {$dir}");
        $this->cleanup[] = $dir;

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
