<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Response\RouteTemplateSet;

/**
 * Stamps each mixed GET route entry with the indices of its bundles that can render as a real page.
 *
 * A route key can carry several bundles, and only some of them have a rich route rule (or are binary).
 * At serve time the engine prefers a real page over bare matcher words (Honeypot::buildRouteFake), but
 * scanning every route rule per request is too slow, so the build records the candidates once as
 * `$entry['rb']` — a list of indices into `$entry['b']`.
 *
 * Only mixed GET keys are stamped: all-rich and bait-only keys stay byte-identical, and `GET /` is the
 * persona root (Honeypot::personaGateAllows re-picks over its full candidate set), so it is never
 * stamped. The pass strips every existing stamp first, so it is idempotent and an index folded in place
 * never keeps a stale one (RouteIndexFold re-indexes `b`).
 */
final class RichBundleStamp
{
    public const KEY = 'rb';

    /**
     * @param array<string,mixed> $index schema-1 index (templates + routes)
     * @return array{index: array<string,mixed>, stamped: int}
     */
    public function apply(array $index, RouteTemplateSet $routes): array
    {
        $stamped = 0;
        foreach ((array) ($index['routes'] ?? []) as $key => $entry) {
            if (!is_array($entry)) {
                continue;
            }
            unset($entry[self::KEY]);

            $key = (string) $key;
            $bundles = array_values((array) ($entry['b'] ?? []));
            if (strncmp($key, 'GET ', 4) === 0 && $key !== 'GET /' && $bundles !== []) {
                $rich = [];
                foreach ($bundles as $i => $bundle) {
                    if (!is_array($bundle)) {
                        continue;
                    }
                    if (!empty($bundle['bin']) || $routes->findRule($bundle, $key) !== null) {
                        $rich[] = $i;
                    }
                }
                if ($rich !== [] && count($rich) < count($bundles)) {
                    $entry[self::KEY] = $rich;
                    $stamped++;
                }
            }

            $index['routes'][$key] = $entry;
        }

        return ['index' => $index, 'stamped' => $stamped];
    }
}
