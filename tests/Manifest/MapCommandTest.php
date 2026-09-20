<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Manifest;

use PHPUnit\Framework\TestCase;

/**
 * `bin/funnypot map` CLI contract (FP-0004): the disjoint write/preview modes, bounded exit codes,
 * and preview-never-mutates guarantee. Shells out to the real binary against the committed manifest,
 * matching ArtifactDeterminismTest's exec pattern.
 *
 * Write mode is exercised idempotently: `map` reproduces the committed docs/DECOY-MAP.md + README
 * block byte-for-byte, so running it here leaves no net change (the property check-drift relies on).
 */
final class MapCommandTest extends TestCase
{
    private function bin(): string
    {
        return escapeshellarg(__DIR__ . '/../../bin/funnypot');
    }

    /**
     * @return array{0:int,1:string,2:string} [exitCode, stdout, stderr]
     */
    private function runCli(string $args): array
    {
        $cmd = 'php -d memory_limit=1G ' . $this->bin() . ' map ' . $args;
        $descriptors = array(1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
        $proc = proc_open($cmd, $descriptors, $pipes, __DIR__ . '/../..');
        self::assertIsResource($proc, "failed to launch: {$cmd}");
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($proc);

        return array($code, $stdout, $stderr);
    }

    private function repoPath(string $rel): string
    {
        return __DIR__ . '/../../' . $rel;
    }

    // ---- preview modes -----------------------------------------------------

    public function testPreviewMarkdownOverview(): void
    {
        list($code, $out) = $this->runCli('--format=md');
        self::assertSame(0, $code);
        self::assertStringContainsString('# Decoy map', $out);
        self::assertStringContainsString('Authored records: 322', $out);
    }

    public function testPreviewMermaidOverview(): void
    {
        list($code, $out) = $this->runCli('--format=mermaid');
        self::assertSame(0, $code);
        self::assertStringStartsWith('mindmap', $out);
    }

    public function testPreviewFamilyMarkdown(): void
    {
        list($code, $out) = $this->runCli('--family=phpmyadmin');
        self::assertSame(0, $code);
        self::assertStringContainsString('Decoy family: phpmyadmin', $out);
    }

    public function testPreviewFamilyMermaid(): void
    {
        list($code, $out) = $this->runCli('--family=phpmyadmin --format=mermaid');
        self::assertSame(0, $code);
        self::assertStringStartsWith('flowchart TD', $out);
    }

    public function testPreviewWritesNothing(): void
    {
        $mapPath = $this->repoPath('docs/DECOY-MAP.md');
        $readmePath = $this->repoPath('README.md');
        $beforeMap = is_file($mapPath) ? md5_file($mapPath) : null;
        $beforeReadme = md5_file($readmePath);

        $this->runCli('--format=md');
        $this->runCli('--family=phpmyadmin');
        $this->runCli('--format=mermaid');

        self::assertSame($beforeMap, is_file($mapPath) ? md5_file($mapPath) : null, 'preview mutated the map');
        self::assertSame($beforeReadme, md5_file($readmePath), 'preview mutated the README');
    }

    // ---- error modes (exit 2) ----------------------------------------------

    public function testInvalidFormatExit2(): void
    {
        list($code) = $this->runCli('--format=xml');
        self::assertSame(2, $code);
    }

    public function testPositionalArgExit2(): void
    {
        list($code) = $this->runCli('foo');
        self::assertSame(2, $code);
    }

    public function testDuplicateFormatExit2(): void
    {
        list($code) = $this->runCli('--format=md --format=mermaid');
        self::assertSame(2, $code);
    }

    public function testDuplicateFamilyExit2(): void
    {
        list($code) = $this->runCli('--family=a --family=b');
        self::assertSame(2, $code);
    }

    public function testEmptyFamilyExit2(): void
    {
        list($code) = $this->runCli('--family=');
        self::assertSame(2, $code);
    }

    public function testUnknownFamilyExit2(): void
    {
        list($code) = $this->runCli('--family=does-not-exist-zzz');
        self::assertSame(2, $code);
    }

    // ---- write mode --------------------------------------------------------

    public function testWriteModeIsIdempotent(): void
    {
        $mapPath = $this->repoPath('docs/DECOY-MAP.md');
        $readmePath = $this->repoPath('README.md');

        list($code1) = $this->runCli('');
        self::assertSame(0, $code1);
        $map1 = file_get_contents($mapPath);
        $readme1 = file_get_contents($readmePath);

        list($code2) = $this->runCli('');
        self::assertSame(0, $code2);
        $map2 = file_get_contents($mapPath);
        $readme2 = file_get_contents($readmePath);

        self::assertSame($map1, $map2, 'write mode is not idempotent for the map');
        self::assertSame($readme1, $readme2, 'write mode is not idempotent for the README');

        self::assertStringContainsString('<!-- GENERATED-DECOY-INVENTORY:START -->', $readme1);
        self::assertStringContainsString('<!-- GENERATED-DECOY-INVENTORY:END -->', $readme1);
        self::assertStringContainsString('Authored decoy records | 322', $readme1);
        self::assertStringContainsString('# Decoy map', $map1);
        self::assertSame("\n", substr($map1, -1));
    }
}
