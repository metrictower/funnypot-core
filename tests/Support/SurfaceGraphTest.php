<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SurfaceGraph;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * FP-0278 — the SurfaceGraph helper contract. SurfaceGraph is the single source of truth for the
 * per-deploy-seeded decoy surface graph: it must be a pure, deterministic function of the identity
 * seed (SubSeed::index/subset/permute, never the 64-bit-only child seed), vary the endpoint
 * set/order/nouns across deploys, keep every within-deploy structural invariant the coherence gate
 * relies on, and stay pinned to the compiled superset (398/399 `paths:` and the surface-owned keys)
 * so the pool and the artifact can never drift.
 *
 * These assertions FAIL against pre-FP-0278 code (there was no SurfaceGraph and the graph was a
 * fleet constant). Fixtures: the committed templates/route/398-rest-collection.yaml +
 * 399-rest-detail.yaml (superset pin) and resources/compiled/nuclei-index.full.php (ownership pin).
 */
final class SurfaceGraphTest extends TestCase
{
    private const TEMPLATES = __DIR__ . '/../../templates/route';
    private const FULL_INDEX = __DIR__ . '/../../resources/compiled/nuclei-index.full.php';

    /** The determinism-check seeds (materials seeded exactly as a deploy would). */
    private function determinismSeeds(): array
    {
        return [
            0,
            1,
            PersonaIdentity::seedFromMaterial(''),
            PersonaIdentity::seedFromMaterial('funnypot'),
            PersonaIdentity::seedFromMaterial('a'),
            PersonaIdentity::seedFromMaterial('b'),
        ];
    }

    /** 64 distinct deploy materials for the variance + structural sweeps. */
    private function sweepSeeds(): array
    {
        $seeds = [];
        for ($i = 0; $i < 64; $i++) {
            $seeds[] = PersonaIdentity::seedFromMaterial('fp-0278-m' . $i);
        }

        return $seeds;
    }

    /** Segment-aware "does $root cover $p" — the same rule the coherence gate uses. */
    private static function covers(string $root, string $p): bool
    {
        return $p === $root || strpos($p, $root . '/') === 0;
    }

    // --- determinism ------------------------------------------------------------------------------

    public function test_every_derivation_is_deterministic_within_a_deploy(): void
    {
        foreach ($this->determinismSeeds() as $seed) {
            self::assertSame(SurfaceGraph::nouns($seed), SurfaceGraph::nouns($seed), "nouns seed={$seed}");
            self::assertSame(SurfaceGraph::sitemapPaths($seed), SurfaceGraph::sitemapPaths($seed), "sitemapPaths seed={$seed}");
            self::assertSame(SurfaceGraph::disallowPaths($seed), SurfaceGraph::disallowPaths($seed), "disallowPaths seed={$seed}");
            self::assertSame(SurfaceGraph::sitemapBlock($seed, 'ex.test'), SurfaceGraph::sitemapBlock($seed, 'ex.test'), "sitemapBlock seed={$seed}");
            self::assertSame(SurfaceGraph::disallowBlock($seed), SurfaceGraph::disallowBlock($seed), "disallowBlock seed={$seed}");
        }
    }

    // --- cross-deploy variance --------------------------------------------------------------------

    public function test_the_graph_varies_across_deploys_on_all_three_axes(): void
    {
        $tuples = [];
        $nounSets = [];
        $sitemapOrders = [];
        $disallowOrders = [];
        foreach ($this->sweepSeeds() as $seed) {
            $sitemap = SurfaceGraph::sitemapPaths($seed);
            $disallow = SurfaceGraph::disallowPaths($seed);
            $nouns = SurfaceGraph::nouns($seed);
            $tuples[serialize([$sitemap, $disallow, $nouns])] = true;
            $nounSets[serialize($nouns)] = true;
            $sitemapOrders[serialize($sitemap)] = true;
            $disallowOrders[serialize($disallow)] = true;
        }
        self::assertGreaterThanOrEqual(60, count($tuples), 'the graph must be near-unique across 64 deploys');
        // Each axis independently live: >1 distinct value proves the axis is not frozen.
        self::assertGreaterThan(1, count($nounSets), 'the noun set must vary across deploys');
        self::assertGreaterThan(1, count($sitemapOrders), 'the sitemap set/order must vary across deploys');
        self::assertGreaterThan(1, count($disallowOrders), 'the Disallow set/order must vary across deploys');
    }

    // --- structural invariants at every sampled seed ----------------------------------------------

    public function test_structural_invariants_hold_at_every_seed(): void
    {
        $v1Present = false;
        $v1Absent = false;
        $optionalDocs = SurfaceGraph::OPTIONAL_DOCS;
        foreach ($this->sweepSeeds() as $seed) {
            $nouns = SurfaceGraph::nouns($seed);
            self::assertNotSame($nouns['c1'], $nouns['c2'], "seed={$seed}: collection nouns must be distinct");
            self::assertNotSame($nouns['d1'], $nouns['d2'], "seed={$seed}: detail nouns must be distinct");
            self::assertContains($nouns['c1'], SurfaceGraph::COLLECTION_NOUNS, "seed={$seed}: c1 in collection pool");
            self::assertContains($nouns['c2'], SurfaceGraph::COLLECTION_NOUNS, "seed={$seed}: c2 in collection pool");
            self::assertContains($nouns['d1'], SurfaceGraph::DETAIL_NOUNS, "seed={$seed}: d1 in detail pool");
            self::assertContains($nouns['d2'], SurfaceGraph::DETAIL_NOUNS, "seed={$seed}: d2 in detail pool");

            $sitemap = SurfaceGraph::sitemapPaths($seed);
            self::assertSame(array_values(array_unique($sitemap)), $sitemap, "seed={$seed}: sitemap has no duplicate");

            foreach (SurfaceGraph::SPINE as $spine) {
                self::assertContains($spine, $sitemap, "seed={$seed}: SPINE path {$spine} must be advertised");
            }

            $optionalIn = array_values(array_intersect($optionalDocs, $sitemap));
            self::assertGreaterThanOrEqual(3, count($optionalIn), "seed={$seed}: >=3 optional docs advertised");
            self::assertLessThanOrEqual(6, count($optionalIn), "seed={$seed}: <=6 optional docs advertised");

            if (in_array(SurfaceGraph::OPTIONAL_ROOT, $sitemap, true)) {
                $v1Present = true;
            } else {
                $v1Absent = true;
            }

            foreach (SurfaceGraph::NEVER_IN_SITEMAP as $never) {
                self::assertNotContains($never, $sitemap, "seed={$seed}: ops path {$never} must never be sitemapped");
            }

            $disallow = SurfaceGraph::disallowPaths($seed);
            self::assertSame(SurfaceGraph::ROBOTS_FIXED, $disallow[0], "seed={$seed}: /admin must be the first Disallow");
            foreach (SurfaceGraph::ROBOTS_REQUIRED as $req) {
                self::assertContains($req, $disallow, "seed={$seed}: required root {$req} must be disallowed");
            }

            // C3 at the helper level: no sitemap path is prefix-covered by a Disallow root.
            foreach ($sitemap as $loc) {
                foreach ($disallow as $root) {
                    self::assertFalse(self::covers($root, $loc), "seed={$seed}: sitemap {$loc} must not be covered by Disallow {$root}");
                }
            }

            // sitemapBlock lines are well-formed, directive-free and digit-free.
            $block = SurfaceGraph::sitemapBlock($seed, 'nimvello.test');
            self::assertStringNotContainsString('{{', $block, "seed={$seed}: sitemap block carries no residual directive");
            // No bare 6-digit run (the fingerprint denylist token \b9\d{5}\b); the version digits in
            // /api/v1, /v2/api-docs etc. are single digits and fingerprint-safe.
            self::assertDoesNotMatchRegularExpression('/\d{6}/', $block, "seed={$seed}: sitemap block carries no 6-digit run");
            foreach (explode("\n", $block) as $line) {
                self::assertMatchesRegularExpression('#^<url><loc>https://nimvello\.test/[^<]+</loc></url>$#', $line, "seed={$seed}: sitemap line shape");
            }
            $dblock = SurfaceGraph::disallowBlock($seed);
            self::assertStringNotContainsString('{{', $dblock, "seed={$seed}: disallow block carries no residual directive");
            self::assertStringStartsWith('Disallow: /admin', $dblock, "seed={$seed}: disallow block starts with /admin");
        }
        self::assertTrue($v1Present, 'the /v1 alias must be advertised for some deploys');
        self::assertTrue($v1Absent, 'the /v1 alias must be absent for some deploys');
    }

    // --- superset pin -----------------------------------------------------------------------------

    public function test_398_paths_equal_the_collection_pool(): void
    {
        $doc = Yaml::parseFile(self::TEMPLATES . '/398-rest-collection.yaml');
        $paths = $doc['new_page']['paths'];
        sort($paths);
        $pool = SurfaceGraph::collectionPaths();
        sort($pool);
        self::assertSame($pool, $paths, '398-rest-collection.yaml paths: must equal SurfaceGraph::collectionPaths()');
    }

    public function test_399_paths_equal_the_detail_pool(): void
    {
        $doc = Yaml::parseFile(self::TEMPLATES . '/399-rest-detail.yaml');
        $paths = $doc['new_page']['paths'];
        sort($paths);
        $pool = SurfaceGraph::detailPaths();
        sort($pool);
        self::assertSame($pool, $paths, '399-rest-detail.yaml paths: must equal SurfaceGraph::detailPaths()');
    }

    public function test_every_sitemap_noun_path_is_in_the_advertisable_superset(): void
    {
        $superset = array_merge(
            SurfaceGraph::allCandidatePaths(),
            SurfaceGraph::SPINE,
            SurfaceGraph::OPTIONAL_DOCS,
            [SurfaceGraph::OPTIONAL_ROOT]
        );
        foreach ($this->sweepSeeds() as $seed) {
            foreach (SurfaceGraph::sitemapPaths($seed) as $loc) {
                self::assertContains($loc, $superset, "seed={$seed}: advertised {$loc} must be in the compiled superset");
            }
        }
    }

    public function test_collection_and_detail_pools_are_disjoint(): void
    {
        self::assertSame([], array_values(array_intersect(SurfaceGraph::COLLECTION_NOUNS, SurfaceGraph::DETAIL_NOUNS)), 'noun pools must be disjoint so a noun slot class is unambiguous');
    }

    // --- surface ownership (the merge-routes w=8 demotion trap), co-tenants tolerated -------------

    public function test_every_candidate_path_is_surface_owned_and_uncapped(): void
    {
        if (!is_file(self::FULL_INDEX)) {
            self::markTestSkipped('nuclei-index.full.php not built — run bin/funnypot build');
        }
        $index = require self::FULL_INDEX;
        $routes = $index['routes'] ?? $index;
        $surfacePids = ['route-surface-collection', 'route-surface-detail'];
        foreach (SurfaceGraph::allCandidatePaths() as $path) {
            $key = 'GET ' . $path;
            self::assertArrayHasKey($key, $routes, "candidate {$path} must be a compiled route key");
            $entry = $routes[$key];
            self::assertArrayNotHasKey('d', $entry, "candidate {$path} must NOT be capped (a 'd' list triggers the merge-routes w=8 demotion)");
            $surfaceBundles = 0;
            foreach (($entry['b'] ?? []) as $bundle) {
                if (in_array($bundle['pid'] ?? '', $surfacePids, true)) {
                    $surfaceBundles++;
                    self::assertSame(100000, $bundle['w'] ?? null, "candidate {$path}: the surface bundle must serve at weight 100000");
                }
            }
            self::assertSame(1, $surfaceBundles, "candidate {$path} must carry exactly one surface bundle (corpus co-tenants tolerated)");
        }
    }

    // --- 32-bit safety ----------------------------------------------------------------------------

    public function test_surface_graph_never_calls_the_64bit_child_seed(): void
    {
        // The served path must reduce through the 32-bit-safe SubSeed::index/subset/permute, never the
        // 64-bit-only child seed (which overflows a 32-bit int). Grep the source the way SubSeedTest
        // greps src/ for tags.
        $src = (string) file_get_contents((new \ReflectionClass(SurfaceGraph::class))->getFileName());
        self::assertStringNotContainsString('SubSeed::int(', $src, 'SurfaceGraph must not use the 64-bit-only child seed on the served path');
    }
}
