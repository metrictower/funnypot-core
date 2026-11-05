<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Response\RouteTemplateSet;

/**
 * Stamps each mixed GET route entry with the indices of the bundles the engine should prefer as a real
 * page: those with a rich route rule that are neither binary nor a 5xx error page.
 *
 * A route key can carry several bundles, and only some of them have a rich route rule. At serve time the
 * engine prefers a real page over bare matcher words (Honeypot::buildRouteFake), but scanning every route
 * rule per request is too slow, so the build records the candidates once as `$entry['rb']` — a list of
 * indices into `$entry['b']`.
 *
 * Only mixed GET keys are stamped: all-rich and bait-only keys stay byte-identical, and `GET /` is the
 * persona root (Honeypot::personaGateAllows re-picks over its full candidate set), so it is never
 * stamped. Binary bundles stay out: a favicon or image is one fixed hash, so preferring it would serve
 * the same bytes on every host. A 5xx page stays out too: an error is not a real page for a plain request.
 * The pass strips every existing stamp first, so it is idempotent and an index folded in place never
 * keeps a stale one (RouteIndexFold re-indexes `b`).
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
                    if (self::preferable($bundle) && $routes->findRule($bundle, $key) !== null) {
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

    /**
     * Whether a bundle may be preferred as a real page at all: not binary, not a 5xx error. The engine uses
     * the same test to know that a bundle outside the stamp can never render as a real page.
     *
     * @param array<string,mixed> $bundle
     */
    public static function preferable(array $bundle): bool
    {
        return empty($bundle['bin']) && (int) ($bundle['s'] ?? 200) < 500;
    }
}
