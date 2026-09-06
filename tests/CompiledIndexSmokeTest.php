<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * Smoke-loads the compiled full corpus through the existing PhpArrayStore and asserts a
 * handful of well-known scanner probes route. Skips cleanly when the artifact has not
 * been built (the compiler is a separate, host-only step).
 */
final class CompiledIndexSmokeTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';

    private const FRAGMENT = __DIR__ . '/../resources/compiled/funnypot-routes-index.php';

    protected function setUp(): void
    {
        if (!is_file(self::INDEX)) {
            self::markTestSkipped('nuclei-index.full.php not built — run bin/funnypot compile');
        }
    }

    /**
     * @param array<string,mixed> $index
     * @return string[] route keys where EVERY bundle is stamped amb=1
     */
    private static function allAmbientKeys(array $index): array
    {
        $keys = [];
        foreach ($index['routes'] as $key => $entry) {
            $bundles = $entry['b'] ?? [];
            if ($bundles === []) {
                continue;
            }
            foreach ($bundles as $b) {
                if ((int) ($b['amb'] ?? 0) !== 1) {
                    continue 2;
                }
            }
            $keys[] = $key;
        }
        sort($keys);

        return $keys;
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

    public function test_ambient_stamp_lands_on_exactly_the_curated_corpus_keys(): void
    {
        // The curated list ∩ the corpus at the committed pin, plus the one fold-only curated key
        // (/sitemap_index.xml, folded by templates/route/393-sitemap-xml.yaml). If this fails after
        // a deliberate pin move, re-derive the set by hand (plan.md Step 5c) — never edit it to pass.
        self::assertSame([
            'GET /.well-known/apple-app-site-association',
            'GET /.well-known/assetlinks.json',
            'GET /.well-known/dnt-policy.txt',
            'GET /.well-known/security.txt',
            'GET /browserconfig.xml',
            'GET /favicon.ico',
            'GET /manifest.json',
            'GET /robots.txt',
            'GET /sitemap.xml',
            'GET /sitemap_index.xml',
        ], self::allAmbientKeys(require self::INDEX));
    }

    public function test_no_route_key_has_mixed_ambient_stamps(): void
    {
        // Both build halves stamp from one list (Compiler\AmbientPaths). A key whose bundles
        // disagree means one half was rebuilt from a different list revision — or someone
        // re-introduced a per-template amb knob. Either is a broken artifact, not a runtime concern.
        $index = require self::INDEX;
        $mixed = [];
        foreach ($index['routes'] as $key => $entry) {
            $seen = [];
            foreach ($entry['b'] ?? [] as $b) {
                $seen[(int) ($b['amb'] ?? 0)] = true;
            }
            if (count($seen) > 1) {
                $mixed[] = $key;
            }
        }
        self::assertSame([], $mixed, 'route keys with mixed amb stamps — rerun `composer build-corpus`');
    }

    public function test_folded_bundles_in_the_index_match_the_committed_fragment(): void
    {
        // `composer build` refreshes the fragment but an ambient-list edit followed by `build` alone
        // can leave the index stale relative to the fragment on the amb field. Catch that here.
        if (!is_file(self::FRAGMENT)) {
            self::markTestSkipped('funnypot-routes-index.php not built');
        }
        $index = require self::INDEX;
        $fragment = require self::FRAGMENT;
        foreach ($fragment['routes'] as $key => $bundles) {
            foreach ($bundles as $fb) {
                $found = false;
                foreach ($index['routes'][$key]['b'] ?? [] as $ib) {
                    if (($ib['pid'] ?? null) === ($fb['pid'] ?? '~')) {
                        $found = true;
                        self::assertSame((int) ($fb['amb'] ?? 0), (int) ($ib['amb'] ?? 0), "{$key} {$fb['pid']}: fragment and index disagree on amb — run `composer build-corpus`");
                    }
                }
                self::assertTrue($found, "{$key} {$fb['pid']} is in the fragment but not folded into the index");
            }
        }
    }

    public function test_the_fp0053_six_paths_classify_ambient(): void
    {
        $engine = $this->inverter();

        foreach (['/favicon.ico', '/robots.txt', '/sitemap.xml', '/manifest.json', '/browserconfig.xml', '/.well-known/security.txt'] as $path) {
            $verdict = $engine->classify(new RequestContext('GET', $path), SiteProfile::empty());
            self::assertSame(Verdict::AMBIENT, $verdict->classification, $path);
            self::assertNotEmpty($verdict->detection->templateIds(), $path . ' must keep its detection data');
            self::assertNotNull($verdict->fakeHandle, $path . ' must keep its route handle');
        }
    }

    public function test_probes_subpaths_and_the_uncurated_sitemap_alias_classify_scanner_probe(): void
    {
        $engine = $this->inverter();

        // /sitemap shares its new_page template with two curated keys — the per-PATH proof on the real artifact.
        foreach (['/wp-login.php', '/.env', '/.git/config', '/phpmyadmin/index.php', '/actuator/favicon.ico', '/web/manifest.json', '/sitemap'] as $path) {
            $verdict = $engine->classify(new RequestContext('GET', $path), SiteProfile::empty());
            self::assertSame(Verdict::SCANNER_PROBE, $verdict->classification, $path);
        }
    }

    public function test_root_still_classifies_clean(): void
    {
        $verdict = $this->inverter()->classify(new RequestContext('GET', '/'), SiteProfile::empty());

        self::assertSame(Verdict::CLEAN, $verdict->classification);
    }
}
