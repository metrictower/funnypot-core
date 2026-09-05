<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteIndexFold;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The synchronizing fold: merge-routes owns every `route-*` template, bundle and detection in the
 * index, removes them all, then folds the current fragment. A removed or changed new-page can no
 * longer survive a rebuild. Every assertion here fails against the historical additive-by-pid fold
 * (a stale bundle survives, a same-pid change never replaces, a capped `d` never refreshes).
 */
final class RouteIndexFoldTest extends TestCase
{
    /** @return array<string,mixed> */
    private static function baseIndex(): array
    {
        return [
            'schema' => 1,
            'templates' => [
                'x1' => ['name' => 'x1'],
                'y1' => ['name' => 'y1'],
                'y2' => ['name' => 'y2'],
                'z1' => ['name' => 'z1'],
                'route-stale' => ['name' => 'stale'],
                'route-keep' => ['name' => 'old'],
            ],
            'routes' => [
                'GET /a' => ['b' => [
                    ['pid' => 'x1', 's' => 200, 't' => ['x1']],
                    ['pid' => 'route-stale', 's' => 200, 't' => ['route-stale']],
                    ['pid' => 'route-keep', 's' => 200, 't' => ['route-keep']],
                ]],
                'GET /b' => [
                    'd' => ['y1', 'route-stale', 'y2', 'route-keep'],
                    'b' => [
                        ['pid' => 'y1', 's' => 200, 't' => ['y1'], 'w' => 3],
                        ['pid' => 'route-keep', 's' => 200, 't' => ['route-keep'], 'w' => 8],
                    ],
                ],
                'GET /c' => ['b' => [
                    ['pid' => 'route-stale', 's' => 200, 't' => ['route-stale']],
                ]],
                'GET /d' => ['b' => [
                    ['pid' => 'z1', 's' => 200, 't' => ['z1']],
                ]],
            ],
        ];
    }

    /** @return array<string,mixed> */
    private static function fragment(): array
    {
        return [
            'templates' => [
                'route-keep' => ['name' => 'new'],
                'route-new' => ['name' => 'new-page'],
            ],
            'routes' => [
                'GET /a' => [['pid' => 'route-keep', 's' => 201, 't' => ['route-keep']]],
                'GET /b' => [['pid' => 'route-keep', 's' => 200, 't' => ['route-keep']]],
                'GET /e' => [['pid' => 'route-new', 's' => 200, 't' => ['route-new']]],
            ],
        ];
    }

    /** @param array<string,mixed> $entry */
    private static function pids(array $entry): array
    {
        $pids = [];
        foreach ((array) ($entry['b'] ?? []) as $b) {
            $pids[] = $b['pid'] ?? null;
        }

        return $pids;
    }

    public function test_stale_owned_entries_are_removed_everywhere(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        $index = $out['index'];

        self::assertArrayNotHasKey('route-stale', $index['templates'], 'stale template must be gone');
        foreach ($index['routes'] as $key => $entry) {
            self::assertNotContains('route-stale', self::pids($entry), "stale bundle survived at {$key}");
            self::assertNotContains('route-stale', (array) ($entry['d'] ?? []), "stale detection survived at {$key}");
        }
    }

    public function test_owned_only_key_is_dropped_and_unowned_key_is_untouched(): void
    {
        $base = self::baseIndex();
        $out = (new RouteIndexFold())->apply($base, self::fragment());
        $index = $out['index'];

        self::assertArrayNotHasKey('GET /c', $index['routes'], 'owned-only key must drop');
        self::assertSame($base['routes']['GET /d'], $index['routes']['GET /d'], 'unowned key must be byte-equal');
    }

    public function test_new_key_is_created_from_the_fragment(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        self::assertSame(
            ['b' => [['pid' => 'route-new', 's' => 200, 't' => ['route-new']]]],
            $out['index']['routes']['GET /e']
        );
    }

    public function test_same_pid_bundle_is_replaced_in_place_order_kept(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        // The nuclei co-tenant stays first; the owned bundle is replaced by the fragment's (s:201).
        self::assertSame(
            [
                ['pid' => 'x1', 's' => 200, 't' => ['x1']],
                ['pid' => 'route-keep', 's' => 201, 't' => ['route-keep']],
            ],
            $out['index']['routes']['GET /a']['b']
        );
    }

    public function test_capped_key_refreshes_detections_and_reweights(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        $entry = $out['index']['routes']['GET /b'];

        self::assertSame(['y1', 'y2', 'route-keep'], $entry['d'], 'd must drop the stale id and keep the kept one, order preserved');
        self::assertSame(['y1', 'route-keep'], self::pids($entry));
        self::assertSame(3, $entry['b'][0]['w'], 'nuclei co-tenant weight untouched');
        self::assertSame(8, $entry['b'][1]['w'], 'folded bundle re-tiered to 8 on a capped key');
    }

    public function test_template_map_order_is_unowned_then_fragment(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        self::assertSame(
            ['x1', 'y1', 'y2', 'z1', 'route-keep', 'route-new'],
            array_keys($out['index']['templates'])
        );
        self::assertSame('new', $out['index']['templates']['route-keep']['name'], 'template metadata replaced');
    }

    public function test_stats_are_net_not_gross(): void
    {
        $out = (new RouteIndexFold())->apply(self::baseIndex(), self::fragment());
        self::assertSame(
            [
                'stale_templates' => 1,
                'stale_bundles' => 2,
                'stale_detections' => 1,
                'replaced_bundles' => 2,
                'dropped_keys' => 1,
                'folded' => 3,
            ],
            $out['stats']
        );
    }

    public function test_second_fold_is_byte_identical_and_reports_no_stale(): void
    {
        $fold = new RouteIndexFold();
        $first = $fold->apply(self::baseIndex(), self::fragment());
        $second = $fold->apply($first['index'], self::fragment());

        self::assertSame($first['index'], $second['index'], 'a re-fold must be idempotent');
        self::assertSame(
            [
                'stale_templates' => 0,
                'stale_bundles' => 0,
                'stale_detections' => 0,
                'replaced_bundles' => 3,
                'dropped_keys' => 0,
                'folded' => 3,
            ],
            $second['stats']
        );
    }

    // --- fail-closed validation ----------------------------------------------------------------

    public function test_rejects_fragment_template_key_without_the_reserved_prefix(): void
    {
        $frag = self::fragment();
        $frag['templates']['npmrc-page'] = ['name' => 'x'];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/npmrc-page/');
        (new RouteIndexFold())->apply(self::baseIndex(), $frag);
    }

    public function test_rejects_fragment_bundle_with_no_matching_template(): void
    {
        $frag = self::fragment();
        $frag['routes']['GET /f'] = [['pid' => 'route-x', 's' => 200, 't' => ['route-x']]];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/route-x/');
        (new RouteIndexFold())->apply(self::baseIndex(), $frag);
    }

    public function test_rejects_fragment_bundle_without_a_string_pid(): void
    {
        $frag = self::fragment();
        $frag['routes']['GET /a'] = [['s' => 200, 't' => []]];
        $this->expectException(RuntimeException::class);
        (new RouteIndexFold())->apply(self::baseIndex(), $frag);
    }

    public function test_rejects_fragment_key_listing_a_pid_twice(): void
    {
        $frag = self::fragment();
        $frag['routes']['GET /a'] = [
            ['pid' => 'route-keep', 's' => 200, 't' => ['route-keep']],
            ['pid' => 'route-keep', 's' => 201, 't' => ['route-keep']],
        ];
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/route-keep/');
        (new RouteIndexFold())->apply(self::baseIndex(), $frag);
    }

    public function test_rejects_index_route_entry_whose_b_is_not_a_list(): void
    {
        $index = self::baseIndex();
        $index['routes']['GET /a']['b'] = ['pid' => 'x1'];
        $this->expectException(RuntimeException::class);
        (new RouteIndexFold())->apply($index, self::fragment());
    }

    public function test_rejects_index_detection_that_is_not_a_string(): void
    {
        $index = self::baseIndex();
        $index['routes']['GET /b']['d'] = ['y1', 42];
        $this->expectException(RuntimeException::class);
        (new RouteIndexFold())->apply($index, self::fragment());
    }

    public function test_rejects_a_non_schema_1_index(): void
    {
        $index = self::baseIndex();
        $index['schema'] = 2;
        $this->expectException(RuntimeException::class);
        (new RouteIndexFold())->apply($index, self::fragment());
    }
}
