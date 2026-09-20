<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Manifest;

use Funnypot\Core\Manifest\MapRenderer;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * MapRenderer (FP-0004) — the pure, deterministic manifest -> decoy-map transformation.
 *
 * The renderer is inventory-truthful, injection-safe and order-insensitive; these tests pin those
 * properties against small fixtures and the committed manifest. No filesystem/CLI here — the command
 * contract lives in MapCommandTest.
 */
final class MapRendererTest extends TestCase
{
    private function record(string $id, string $family, array $overrides = array()): array
    {
        return array_merge(array(
            'id' => $id,
            'tier' => 'new-page',
            'family' => $family,
            'severity' => 'medium',
            'unanchored' => false,
            'owned_routes' => array(array('method' => 'GET', 'path' => '/' . $id, 'via' => 'route-key')),
            'outbound_links' => array(),
            'tags' => array(),
            'priority' => null,
        ), $overrides);
    }

    private function manifest(array $records, array $corpusFamilies = array('x'), array $corpusIndex = array('GET /x' => 'x'), array $enrichers = array(array('id' => 'e'))): array
    {
        return array(
            'schema' => 1,
            'counts' => array(
                'band_a' => count($records),
                'corpus_families' => count($corpusFamilies),
                'corpus_keys' => count($corpusIndex),
                'enrichers' => count($enrichers),
            ),
            'bandA' => $records,
            'corpus' => array('families' => $corpusFamilies, 'index' => $corpusIndex),
            'enrichers' => $enrichers,
        );
    }

    private function committed(): array
    {
        return require __DIR__ . '/../../resources/compiled/funnypot-manifest.php';
    }

    // ---- validation --------------------------------------------------------

    public function testRejectsWrongSchema(): void
    {
        $m = $this->manifest(array($this->record('a', 'fam')));
        $m['schema'] = 2;
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($m);
    }

    public function testRejectsCountMismatch(): void
    {
        $m = $this->manifest(array($this->record('a', 'fam')));
        $m['counts']['band_a'] = 99;
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($m);
    }

    public function testRejectsCorpusCountMismatch(): void
    {
        $m = $this->manifest(array($this->record('a', 'fam')));
        $m['counts']['corpus_keys'] = 999;
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($m);
    }

    public function testRejectsDuplicateId(): void
    {
        $m = $this->manifest(array($this->record('dup', 'fam'), $this->record('dup', 'other')));
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($m);
    }

    public function testRejectsMalformedRecordMissingTier(): void
    {
        $rec = $this->record('a', 'fam');
        unset($rec['tier']);
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
    }

    public function testRejectsNonBoolUnanchored(): void
    {
        $rec = $this->record('a', 'fam', array('unanchored' => 'yes'));
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
    }

    public function testRejectsNul(): void
    {
        $rec = $this->record("a\0b", 'fam');
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
    }

    public function testRejectsInvalidUtf8(): void
    {
        $rec = $this->record("a", 'fam', array('family' => "\xff\xfe"));
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
    }

    public function testRejectsScalarOverCeiling(): void
    {
        $rec = $this->record('a', str_repeat('x', MapRenderer::MAX_SCALAR_BYTES + 1));
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
    }

    // ---- committed-manifest facts ------------------------------------------

    public function testCommittedOverviewHasExactCounts(): void
    {
        $md = (new MapRenderer())->renderMarkdown($this->committed());
        // Current golden pins (Phase-0 re-ground 2026-09-20).
        self::assertStringContainsString('Authored records: 322 across 78 families', $md);
        self::assertStringContainsString('2611 families / 5134 route keys', $md);
        self::assertStringContainsString('Enrichers: 208', $md);
    }

    public function testCommittedOverviewHasOneCorpusAndEnricherRowOnly(): void
    {
        $md = (new MapRenderer())->renderMarkdown($this->committed());
        self::assertSame(1, substr_count($md, '_corpus (nuclei-inversion)_'));
        self::assertSame(1, substr_count($md, '_content enrichers (not route claimers)_'));
    }

    public function testCommittedOverviewNeverEnumeratesCorpusMembers(): void
    {
        $m = $this->committed();
        // Inject unique sentinels into corpus family/index; they must never appear in output.
        $m['corpus']['families'][] = 'CORPUS_FAMILY_SENTINEL_ZZZ';
        $m['corpus']['index']['GET /corpus-key-sentinel-zzz'] = 'CORPUS_FAMILY_SENTINEL_ZZZ';
        $m['counts']['corpus_families']++;
        $m['counts']['corpus_keys']++;
        $md = (new MapRenderer())->renderMarkdown($m);
        self::assertStringNotContainsString('CORPUS_FAMILY_SENTINEL_ZZZ', $md);
        self::assertStringNotContainsString('corpus-key-sentinel-zzz', $md);
    }

    public function testEndsInExactlyOneLf(): void
    {
        $md = (new MapRenderer())->renderMarkdown($this->committed());
        self::assertSame("\n", substr($md, -1));
        self::assertNotSame("\n\n", substr($md, -2));
    }

    public function testNoTimestampOrHostPath(): void
    {
        $md = (new MapRenderer())->renderMarkdown($this->committed());
        self::assertDoesNotMatchRegularExpression('/\d{4}-\d{2}-\d{2}T/', $md);
        self::assertStringNotContainsString('/Users/', $md);
        self::assertStringNotContainsString(getcwd(), $md);
    }

    // ---- determinism -------------------------------------------------------

    public function testShuffledInputIsByteIdentical(): void
    {
        $records = array(
            $this->record('b', 'beta', array('owned_routes' => array(
                array('method' => 'GET', 'path' => '/b1', 'via' => 'route-key'),
                array('method' => 'POST', 'path' => '/b2', 'via' => 'owns_path'),
            ), 'outbound_links' => array(
                array('path' => 'x', 'source' => 'href', 'relative' => true),
                array('path' => 'y', 'source' => 'location', 'relative' => false),
            ))),
            $this->record('a', 'alpha'),
            $this->record('c', 'beta'),
        );
        $renderer = new MapRenderer();
        $baseline = $renderer->renderMarkdown($this->manifest($records));

        for ($i = 0; $i < 5; $i++) {
            $shuffled = $records;
            shuffle($shuffled);
            foreach ($shuffled as &$r) {
                shuffle($r['owned_routes']);
                shuffle($r['outbound_links']);
            }
            unset($r);
            self::assertSame($baseline, $renderer->renderMarkdown($this->manifest($shuffled)), 'shuffle changed bytes');
        }
    }

    public function testCommittedOutputIsIdempotent(): void
    {
        $renderer = new MapRenderer();
        $m = $this->committed();
        self::assertSame($renderer->renderMarkdown($m), $renderer->renderMarkdown($m));
        self::assertSame($renderer->renderMermaid($m), $renderer->renderMermaid($m));
    }

    // ---- escaping / injection ----------------------------------------------

    public function testInjectionStaysOneLabelAndCell(): void
    {
        $evil = '"] --> evil["  %%{init:x}%% | ``` <script>alert(1)</script> &#124;' . "\r\n\t";
        $rec = $this->record('a', $evil, array('owned_routes' => array(
            array('method' => 'GET', 'path' => $evil, 'via' => 'owns_path'),
        ), 'outbound_links' => array(
            array('path' => $evil, 'source' => 'href', 'relative' => true),
        )));
        $renderer = new MapRenderer();
        $md = $renderer->renderMarkdown($this->manifest(array($rec)), array(), $evil);
        $mermaid = $renderer->renderMermaid($this->manifest(array($rec)), array(), $evil);

        foreach (array($md, $mermaid) as $out) {
            self::assertStringNotContainsString('"] -->', $out);
            self::assertStringNotContainsString('%%{init', $out);
            self::assertStringNotContainsString('<script>', $out);
            self::assertStringNotContainsString("\r", $out);
        }
        // Data pipes never become table columns: no raw pipe from the payload survives in md cells.
        // The generator's own table pipes remain, but the injected literal `|` is entity-encoded.
        self::assertStringContainsString('&#124;', $md);
        // The injected code-fence text is encoded, not a real fence: no 4th ``` beyond the two the
        // generator emits around the mermaid block.
        self::assertSame(2, substr_count($md, '```'));
    }

    public function testEntityTextIsReEncodedNotDecoded(): void
    {
        // A pre-encoded pipe entity must be treated as data (re-encoded), never as a pipe.
        $rec = $this->record('a', 'fam&#124;name');
        $md = (new MapRenderer())->renderMarkdown($this->manifest(array($rec)));
        // Every non-whitelisted byte of the pre-encoded entity is re-encoded: & # ; all become
        // entities, so the literal text survives as data and never resolves to a pipe.
        self::assertStringContainsString('fam&#38;&#35;124&#59;name', $md);
    }

    public function testMermaidNodeIdsAreOrdinalNotData(): void
    {
        $rec = $this->record('weird id with spaces', 'fam');
        $mermaid = (new MapRenderer())->renderMermaid($this->manifest(array($rec)), array(), 'fam');
        self::assertStringContainsString('fam0001[', $mermaid);
        self::assertStringContainsString('dec0001[', $mermaid);
        // The raw id only ever appears inside a quoted label, never as a bare node id.
        self::assertStringNotContainsString('weird id with spaces[', $mermaid);
    }

    // ---- family isolation + labelling --------------------------------------

    public function testFamilyDrillDownIsIsolated(): void
    {
        $records = array($this->record('a', 'alpha'), $this->record('b', 'beta'));
        $md = (new MapRenderer())->renderMarkdown($this->manifest($records), array(), 'alpha');
        self::assertStringContainsString('Decoy family: alpha', $md);
        self::assertStringNotContainsString('## b', $md);
    }

    public function testUnknownFamilyRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest(array($this->record('a', 'alpha'))), array(), 'ghost');
    }

    public function testUnanchoredAndEmptyLinkLabels(): void
    {
        $rec = $this->record('a', 'fam', array('unanchored' => true, 'owned_routes' => array(), 'outbound_links' => array()));
        $md = (new MapRenderer())->renderMarkdown($this->manifest(array($rec)), array(), 'fam');
        self::assertStringContainsString('unanchored; no route claim in manifest', $md);
        self::assertStringContainsString('no recorded outbound links', $md);
    }

    // ---- findings decoration -----------------------------------------------

    private function finding(string $severity, string $a, string $b = '', string $path = '', string $message = 'msg', array $extra = array()): array
    {
        return array_merge(array(
            'check' => 'collision',
            'severity' => $severity,
            'a' => $a,
            'b' => $b,
            'path' => $path,
            'message' => $message,
        ), $extra);
    }

    public function testFindingsDecorateWithoutChangingInventory(): void
    {
        $records = array($this->record('a', 'fam'));
        $renderer = new MapRenderer();
        $plain = $renderer->renderMarkdown($this->manifest($records), array(), 'fam');
        $findings = array(
            $this->finding('fail', 'a', 'b', '/x', 'boom'),
            $this->finding('warn', 'a'),
            $this->finding('accepted', 'a', '', '', 'ok', array('accepted_reason' => 'reviewed')),
            $this->finding('info', 'a'),
        );
        $decorated = $renderer->renderMarkdown($this->manifest($records), $findings, 'fam');

        // Same record set: one `## a` heading in both.
        self::assertSame(substr_count($plain, '## a'), substr_count($decorated, '## a'));
        self::assertStringContainsString('Route-integrity findings', $decorated);
        self::assertStringContainsString('reviewed', $decorated);
        // Fail sorts before info in the findings table.
        self::assertLessThan(strpos($decorated, '| info |'), strpos($decorated, '| fail |'));
    }

    public function testOverviewIntegrityColumnSummarizesSeverities(): void
    {
        $records = array($this->record('a', 'fam'));
        $findings = array($this->finding('fail', 'a'), $this->finding('warn', 'a'));
        $md = (new MapRenderer())->renderMarkdown($this->manifest($records), $findings);
        self::assertStringContainsString('fail, warn', $md);
    }

    public function testUnknownFindingSeverityRejected(): void
    {
        $records = array($this->record('a', 'fam'));
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->renderMarkdown($this->manifest($records), array($this->finding('critical', 'a')), 'fam');
    }

    // ---- README boundary ---------------------------------------------------

    public function testReplaceReadmePreservesOutsideBytes(): void
    {
        $readme = "PREFIX\n" . MapRenderer::README_START . "\nOLD\n" . MapRenderer::README_END . "\nSUFFIX\n";
        $out = (new MapRenderer())->replaceReadmeInventory($readme, "NEW\n");
        self::assertStringStartsWith("PREFIX\n", $out);
        self::assertStringEndsWith("\nSUFFIX\n", $out);
        self::assertStringContainsString("NEW\n", $out);
        self::assertStringNotContainsString('OLD', $out);
    }

    public function testReplaceReadmeIsIdempotent(): void
    {
        $renderer = new MapRenderer();
        $inv = $renderer->renderReadmeInventory($this->committed());
        $readme = "A\n" . MapRenderer::README_START . "\nstale\n" . MapRenderer::README_END . "\nB\n";
        $once = $renderer->replaceReadmeInventory($readme, $inv);
        $twice = $renderer->replaceReadmeInventory($once, $inv);
        self::assertSame($once, $twice);
    }

    public function testReplaceReadmeMissingMarkerFails(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->replaceReadmeInventory("no markers here", "NEW\n");
    }

    public function testReplaceReadmeDuplicateMarkerFails(): void
    {
        $readme = MapRenderer::README_START . "\n" . MapRenderer::README_START . "\nx\n" . MapRenderer::README_END . "\n";
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->replaceReadmeInventory($readme, "NEW\n");
    }

    public function testReplaceReadmeReversedMarkerFails(): void
    {
        $readme = MapRenderer::README_END . "\nx\n" . MapRenderer::README_START . "\n";
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->replaceReadmeInventory($readme, "NEW\n");
    }

    public function testReplaceReadmeRejectsMarkerInBody(): void
    {
        $readme = MapRenderer::README_START . "\nx\n" . MapRenderer::README_END . "\n";
        $this->expectException(InvalidArgumentException::class);
        (new MapRenderer())->replaceReadmeInventory($readme, "NEW " . MapRenderer::README_START . "\n");
    }
}
