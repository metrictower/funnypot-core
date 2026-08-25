<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Manifest;

use Funnypot\Core\Manifest\ManifestBuilder;
use PHPUnit\Framework\TestCase;

/**
 * The derived decoy registry (FP-0001). Builds the manifest over the committed compiled artifacts
 * and pins the load-bearing structure: method-scoped ownership (the phpMyAdmin gate/login pair
 * co-own /phpmyadmin by DISTINCT methods), the compile-time outbound-link scan that catches the
 * relative-self-link bug, full Band A id coverage, and a complete Band B path->family index.
 */
final class ManifestBuilderTest extends TestCase
{
    /** @var array<string,mixed> */
    private static $manifest;

    /** @var string */
    private static $root;

    public static function setUpBeforeClass(): void
    {
        self::$root = dirname(__DIR__, 2);
        self::$manifest = (new ManifestBuilder())->build(ManifestBuilder::defaultPaths(self::$root));
    }

    /** @return array<string,array<string,mixed>> id => record */
    private function bandAById(): array
    {
        $out = array();
        foreach (self::$manifest['bandA'] as $rec) {
            $out[$rec['id']] = $rec;
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $record
     * @return array<int,string> methods that own $path
     */
    private function methodsOwning(array $record, string $path): array
    {
        $methods = array();
        foreach ($record['owned_routes'] as $route) {
            if ($route['path'] === $path) {
                $methods[] = $route['method'];
            }
        }
        sort($methods);

        return $methods;
    }

    public function test_manifest_has_two_bands_and_counts(): void
    {
        self::assertSame(ManifestBuilder::SCHEMA, self::$manifest['schema']);
        self::assertArrayHasKey('bandA', self::$manifest);
        self::assertArrayHasKey('corpus', self::$manifest);
        self::assertArrayHasKey('enrichers', self::$manifest);
        self::assertSame(count(self::$manifest['bandA']), self::$manifest['counts']['band_a']);
        self::assertSame(count(self::$manifest['corpus']['index']), self::$manifest['counts']['corpus_keys']);
    }

    public function test_phpmyadmin_gate_and_login_co_own_by_distinct_methods(): void
    {
        $byId = $this->bandAById();
        self::assertArrayHasKey('attack-phpmyadmin-gate', $byId, 'gate record present');
        self::assertArrayHasKey('attack-phpmyadmin-login', $byId, 'login record present');

        $gate = $byId['attack-phpmyadmin-gate'];
        $login = $byId['attack-phpmyadmin-login'];

        // Both claim /phpmyadmin — but by DISTINCT method sets (gate GET/HEAD, login POST), so the
        // manifest records method-scoped ownership rather than a false collision.
        self::assertSame(array('GET', 'HEAD'), $this->methodsOwning($gate, '/phpmyadmin'));
        self::assertSame(array('POST'), $this->methodsOwning($login, '/phpmyadmin'));

        // The claims are disjoint on the shared path.
        self::assertSame(
            array(),
            array_intersect($this->methodsOwning($gate, '/phpmyadmin'), $this->methodsOwning($login, '/phpmyadmin')),
            'gate and login methods are disjoint on /phpmyadmin'
        );

        // Provenance is recorded so the downstream lint can tell an owns_path claim from a static key.
        foreach ($gate['owned_routes'] as $route) {
            self::assertSame('owns_path', $route['via']);
        }
    }

    public function test_compile_time_scan_captures_the_relative_self_link(): void
    {
        // The motivating bug: the phpMyAdmin login body carries a RELATIVE form action
        // (action="index.php?route=/"). The static body scan must surface it as a relative link.
        $gate = $this->bandAById()['attack-phpmyadmin-gate'];

        $found = null;
        foreach ($gate['outbound_links'] as $link) {
            if ($link['source'] === 'form-action') {
                $found = $link;
                break;
            }
        }
        self::assertNotNull($found, 'the form-action link was scanned');
        self::assertSame('index.php', $found['path']);
        self::assertTrue($found['relative'], 'a base-relative self-link is flagged relative');
    }

    public function test_band_a_covers_every_authored_attack_and_param_id(): void
    {
        $byId = $this->bandAById();

        $attack = require self::$root . '/resources/compiled/funnypot-attack.php';
        foreach ($attack as $rule) {
            self::assertArrayHasKey((string) $rule['id'], $byId, 'attack id ' . $rule['id'] . ' has a record');
        }

        $param = require self::$root . '/resources/compiled/funnypot-param.php';
        foreach ((array) $param['buckets'] as $entries) {
            foreach ($entries as $entry) {
                self::assertArrayHasKey((string) $entry['id'], $byId, 'param id ' . $entry['id'] . ' has a record');
            }
        }
    }

    public function test_attack_tiers_are_classified_by_id_prefix(): void
    {
        $byId = $this->bandAById();
        self::assertSame('attack', $byId['attack-phpmyadmin-gate']['tier']);
        self::assertSame('attack-ai', $byId['attack-ai-ollama-tags']['tier']);
        self::assertSame('attack-crs', $byId['attack-crs-sqli']['tier']);
        self::assertSame('param', $byId['param-vite-fs']['tier']);
    }

    public function test_unanchored_class_detector_is_flagged(): void
    {
        $byId = $this->bandAById();
        // A broad payload detector (no in:path condition) fires anywhere — the resolver must know it
        // can swallow an escaped self-link.
        self::assertTrue($byId['attack-sqli']['unanchored']);
        // A path-anchored panel is not unanchored.
        self::assertFalse($byId['attack-phpmyadmin-gate']['unanchored']);
    }

    public function test_band_b_indexes_every_corpus_route_key(): void
    {
        $nuclei = require self::$root . '/resources/compiled/nuclei-index.full.php';
        $index = self::$manifest['corpus']['index'];

        $expected = 0;
        foreach ($nuclei['routes'] as $key => $entry) {
            $isCorpus = false;
            foreach ((array) ($entry['b'] ?? array()) as $bundle) {
                if (strncmp((string) ($bundle['pid'] ?? ''), 'route-', 6) !== 0) {
                    $isCorpus = true;
                    break;
                }
            }
            if ($isCorpus) {
                $expected++;
                self::assertArrayHasKey((string) $key, $index, 'corpus key ' . $key . ' is indexed');
            }
        }
        self::assertSame($expected, count($index), 'index size equals the corpus key count');
    }

    public function test_band_b_entry_carries_family_and_tier(): void
    {
        // A known corpus key resolves to its product family in the index (the resolver's target space).
        $index = self::$manifest['corpus']['index'];
        $key = 'DELETE /dav/server.php/files/personal/GIVE_ME_ERROR_TO_GET_DOC_ROOT_2021';
        self::assertArrayHasKey($key, $index);
        self::assertSame('afterlogic-aurora-webmail', $index[$key]['family']);
        self::assertSame('exact-route', $index[$key]['tier']);
    }

    public function test_folded_new_page_decoys_are_band_a(): void
    {
        // A route-* pid folded route reads as an authored Band A decoy (new-page tier).
        $byId = $this->bandAById();
        self::assertArrayHasKey('GET /api/tags', $byId);
        self::assertSame('new-page', $byId['GET /api/tags']['tier']);

        // A route-only new-page key (no corpus bundle) is Band A and NOT in the Band B corpus index.
        self::assertArrayHasKey('GET /private/', $byId);
        self::assertSame('new-page', $byId['GET /private/']['tier']);
        self::assertArrayNotHasKey('GET /private/', self::$manifest['corpus']['index']);
    }

    public function test_enrichers_listed_apart_from_the_route_space(): void
    {
        $ids = array();
        foreach (self::$manifest['enrichers'] as $e) {
            $ids[$e['id']] = $e['needle'];
        }
        // A content-needle enricher is enumerated with its needle, never as a path claimer.
        self::assertArrayHasKey('route-git-config', $ids);
        self::assertContains('git-config', $ids['route-git-config']);
    }
}
