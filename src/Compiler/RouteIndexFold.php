<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use RuntimeException;

/**
 * Folds the `new_page` fragment (funnypot compile-routes) into the compiled schema-1 index.
 *
 * The fold is SYNCHRONIZING, not additive: it owns every entry whose id matches the reserved
 * `route-` prefix — every template key, bundle `pid` and detection id in the index or fragment
 * matching OWNED_ID_PATTERN — removes all of them, then folds the current fragment. A removed or
 * changed new-page can therefore never survive a rebuild.
 *
 * Ownership is a pure function of the index (no history-bearing generated state), which keeps the
 * fold a pure function of (base index, current fragment) and preserves the zero-drift artifact law.
 * The prefix is reserved at both producers so "owned" and "route-*" can never drift apart:
 * RouteBundleSynth rejects a `new_page` id outside the pattern, and Compiler skips a corpus template
 * that squats it.
 */
final class RouteIndexFold
{
    public const OWNED_ID_PATTERN = '/^route-[a-z0-9-]+$/';

    public static function owns(string $id): bool
    {
        return preg_match(self::OWNED_ID_PATTERN, $id) === 1;
    }

    /**
     * @param array<string,mixed> $index    schema-1 index (templates + routes)
     * @param array<string,mixed> $fragment compile-routes output (templates + routes)
     * @return array{index: array<string,mixed>, stats: array{stale_templates:int, stale_bundles:int,
     *               stale_detections:int, replaced_bundles:int, dropped_keys:int, folded:int}}
     * @throws RuntimeException on a malformed index or fragment (fail closed; nothing is written)
     */
    public function apply(array $index, array $fragment): array
    {
        $this->validateIndex($index);
        $this->validateFragment($fragment);

        // The fragment's owned (key, pid) set: an owned base entry present here is REPLACED, one
        // absent is STALE. Built before any removal so the stats are net, not gross.
        $current = [];
        foreach ($fragment['routes'] as $key => $bundles) {
            foreach ($bundles as $bundle) {
                $current[$key][(string) $bundle['pid']] = true;
            }
        }

        $stats = [
            'stale_templates' => 0,
            'stale_bundles' => 0,
            'stale_detections' => 0,
            'replaced_bundles' => 0,
            'dropped_keys' => 0,
            'folded' => 0,
        ];
        foreach ($index['templates'] as $id => $entry) {
            if (self::owns((string) $id) && !isset($fragment['templates'][$id])) {
                $stats['stale_templates']++;
            }
        }
        foreach ($index['routes'] as $key => $entry) {
            foreach ($entry['b'] as $bundle) {
                $pid = (string) $bundle['pid'];
                if (!self::owns($pid)) {
                    continue;
                }
                if (isset($current[$key][$pid])) {
                    $stats['replaced_bundles']++;
                } else {
                    $stats['stale_bundles']++;
                }
            }
            foreach ((array) ($entry['d'] ?? []) as $did) {
                $did = (string) $did;
                if (self::owns($did) && !isset($current[$key][$did])) {
                    $stats['stale_detections']++;
                }
            }
        }

        // 1. Remove every owned template.
        foreach (array_keys($index['templates']) as $id) {
            if (self::owns((string) $id)) {
                unset($index['templates'][$id]);
            }
        }

        // 2 + 3. Drop every owned bundle/detection from each key; delete a key only when both its
        // bundle list and detection list end up empty (a capped key keeps its uncapped nuclei
        // bundles, so "b empty with d non-empty" cannot arise).
        foreach ($index['routes'] as $key => $entry) {
            $b = [];
            foreach ($entry['b'] as $bundle) {
                if (!self::owns((string) $bundle['pid'])) {
                    $b[] = $bundle;
                }
            }
            $entry['b'] = array_values($b);
            if (isset($entry['d'])) {
                $d = [];
                foreach ($entry['d'] as $did) {
                    if (!self::owns((string) $did)) {
                        $d[] = $did;
                    }
                }
                $entry['d'] = array_values($d);
            }
            if ($entry['b'] === [] && ($entry['d'] ?? []) === []) {
                unset($index['routes'][$key]);
                if (!isset($fragment['routes'][$key])) {
                    $stats['dropped_keys']++;
                }
            } else {
                $index['routes'][$key] = $entry;
            }
        }

        // 4. Add every fragment template. All owned entries were removed in step 1, so these append
        // at the map tail in fragment order — deterministic.
        foreach ($fragment['templates'] as $id => $entry) {
            $index['templates'][$id] = $entry;
        }

        // 5. Fold every fragment bundle once. A new key becomes ['b' => [$bundle]]; an existing
        // capped key keeps detect coverage in 'd' and gives the injected bundle a mid persona tier
        // so it neither dominates nor vanishes. Step 2 already removed any owned bundle, so no pid
        // guard is needed here.
        foreach ($fragment['routes'] as $key => $bundles) {
            foreach ($bundles as $bundle) {
                if (!isset($index['routes'][$key])) {
                    $index['routes'][$key] = ['b' => [$bundle]];
                } else {
                    if (isset($index['routes'][$key]['d'])) {
                        $bundle['w'] = 8;
                        $index['routes'][$key]['d'] = array_values(array_unique(
                            array_merge((array) $index['routes'][$key]['d'], (array) $bundle['t'])
                        ));
                    }
                    $index['routes'][$key]['b'][] = $bundle;
                }
                $stats['folded']++;
            }
        }

        return ['index' => $index, 'stats' => $stats];
    }

    /** @param array<string,mixed> $index */
    private function validateIndex(array $index): void
    {
        if ((int) ($index['schema'] ?? 0) !== 1) {
            throw new RuntimeException('index is not a schema-1 array');
        }
        if (!isset($index['templates']) || !is_array($index['templates'])) {
            throw new RuntimeException('index.templates must be an array');
        }
        if (!isset($index['routes']) || !is_array($index['routes'])) {
            throw new RuntimeException('index.routes must be an array');
        }
        foreach ($index['routes'] as $key => $entry) {
            if (!is_array($entry) || !isset($entry['b']) || !self::isList($entry['b'])) {
                throw new RuntimeException("index route '{$key}' must carry a list 'b'");
            }
            foreach ($entry['b'] as $bundle) {
                if (!is_array($bundle) || !isset($bundle['pid']) || !is_string($bundle['pid'])) {
                    throw new RuntimeException("index route '{$key}' has a bundle without a string pid");
                }
            }
            if (isset($entry['d'])) {
                if (!self::isList($entry['d'])) {
                    throw new RuntimeException("index route '{$key}' detection list 'd' must be a list");
                }
                foreach ($entry['d'] as $did) {
                    if (!is_string($did)) {
                        throw new RuntimeException("index route '{$key}' detection list 'd' contains a non-string");
                    }
                }
            }
        }
    }

    /** @param array<string,mixed> $fragment */
    private function validateFragment(array $fragment): void
    {
        $templates = $fragment['templates'] ?? [];
        $routes = $fragment['routes'] ?? [];
        if (!is_array($templates) || !is_array($routes)) {
            throw new RuntimeException('fragment.templates and fragment.routes must be arrays');
        }
        foreach ($templates as $id => $entry) {
            if (!self::owns((string) $id)) {
                throw new RuntimeException("fragment template id '{$id}' must match the reserved route- prefix");
            }
        }
        foreach ($routes as $key => $bundles) {
            if (!self::isList($bundles)) {
                throw new RuntimeException("fragment route '{$key}' must be a list of bundles");
            }
            $seen = [];
            foreach ($bundles as $bundle) {
                if (!is_array($bundle) || !isset($bundle['pid']) || !is_string($bundle['pid'])) {
                    throw new RuntimeException("fragment route '{$key}' has a bundle without a string pid");
                }
                $pid = $bundle['pid'];
                if (!self::owns($pid)) {
                    throw new RuntimeException("fragment bundle pid '{$pid}' at '{$key}' must match the reserved route- prefix");
                }
                if (!isset($templates[$pid])) {
                    throw new RuntimeException("fragment bundle pid '{$pid}' at '{$key}' has no matching fragment template");
                }
                if (isset($seen[$pid])) {
                    throw new RuntimeException("fragment route '{$key}' lists pid '{$pid}' twice");
                }
                $seen[$pid] = true;
            }
        }
    }

    /** @param mixed $a A zero-indexed sequential array (7.3-safe array_is_list). */
    private static function isList($a): bool
    {
        if (!is_array($a)) {
            return false;
        }

        return $a === [] || array_keys($a) === range(0, count($a) - 1);
    }
}
