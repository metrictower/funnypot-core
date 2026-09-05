<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use RuntimeException;

/**
 * Folds the `new_page` fragment (funnypot compile-routes) into the compiled schema-1 index.
 *
 * The fold owns every entry whose id matches the reserved `route-` prefix — every template key,
 * bundle `pid` and detection id in the index or fragment that matches OWNED_ID_PATTERN. Ownership
 * is a pure function of the index (no history-bearing generated state), which keeps the fold a pure
 * function of (base index, current fragment) and preserves the zero-drift artifact law. The prefix
 * is reserved at both producers so "owned" and "route-*" can never drift apart: RouteBundleSynth
 * rejects a `new_page` id outside the pattern, and Compiler skips a corpus template that squats it.
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
     * @return array{index: array<string,mixed>, stats: array{folded:int}}
     */
    public function apply(array $index, array $fragment): array
    {
        foreach ((array) ($fragment['templates'] ?? []) as $id => $entry) {
            $index['templates'][$id] = $entry;
        }
        $folded = 0;
        foreach ((array) ($fragment['routes'] ?? []) as $key => $bundles) {
            foreach ((array) $bundles as $bundle) {
                if (!isset($index['routes'][$key])) {
                    $index['routes'][$key] = ['b' => [$bundle]];
                } else {
                    foreach ((array) $index['routes'][$key]['b'] as $existing) {
                        if (($existing['pid'] ?? null) === ($bundle['pid'] ?? '~')) {
                            continue 2;
                        }
                    }
                    if (isset($index['routes'][$key]['d'])) {
                        $bundle['w'] = 8;
                        $index['routes'][$key]['d'] = array_values(array_unique(
                            array_merge((array) $index['routes'][$key]['d'], (array) $bundle['t'])
                        ));
                    }
                    $index['routes'][$key]['b'][] = $bundle;
                }
                $folded++;
            }
        }

        return ['index' => $index, 'stats' => ['folded' => $folded]];
    }
}
