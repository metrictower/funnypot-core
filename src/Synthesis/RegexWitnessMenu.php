<?php

declare(strict_types=1);

namespace Funnypot\Core\Synthesis;

use Funnypot\Core\Support\SubSeed;

/**
 * The one render-time selector for the per-deploy regex-witness menu (FP-0280). Given a compiled
 * bundle and the deploy identity, it returns the witness vector this deploy serves — the canonical
 * for every slot with no menu, and a deterministically-chosen alternate for a slot that has one.
 *
 * The choice is keyed on the CANONICAL string (SubSeed::index with NS_WITNESS), so two bundles that
 * share a source-pattern menu select coherently. It is a pure function of (bundle, identitySeed): no
 * clock, request byte, CSPRNG, global counter or SubSeed::int (which is 64-bit-only) enters — a
 * re-scan on one deploy is byte-identical, while different deploys vary. Malformed or out-of-range
 * rxm entries are ignored and leave that slot at its canonical.
 */
final class RegexWitnessMenu
{
    private function __construct()
    {
    }

    /**
     * The selected witness vector, aligned one-for-one with the bundle's `rx` list. Returns [] when
     * the bundle carries no rx.
     *
     * @param array<string,mixed> $bundle a single compiled bundle (entry['b'][i])
     * @return list<string>
     */
    public static function pick(array $bundle, int $identitySeed): array
    {
        $rx = array_values(array_map('strval', (array) ($bundle['rx'] ?? [])));
        if ($rx === []) {
            return [];
        }
        $rxm = is_array($bundle['rxm'] ?? null) ? $bundle['rxm'] : [];

        $selected = [];
        foreach ($rx as $j => $canonical) {
            $options = self::options($canonical, $rxm[$j] ?? null);
            $idx = SubSeed::index($identitySeed, SubSeed::NS_WITNESS, $canonical, count($options));
            $selected[] = $options[$idx];
        }

        return $selected;
    }

    /**
     * [canonical, …distinct-valid-alternates]. Empty, canonical-equal, duplicate and non-string
     * alternates are dropped, so a malformed rxm entry degrades to canonical-only.
     *
     * @param mixed $menu
     * @return list<string>
     */
    private static function options(string $canonical, $menu): array
    {
        $options = [$canonical];
        if (!is_array($menu)) {
            return $options;
        }
        $seen = [$canonical => true];
        foreach ($menu as $alt) {
            if (!is_string($alt) || $alt === '' || isset($seen[$alt])) {
                continue;
            }
            $seen[$alt] = true;
            $options[] = $alt;
        }

        return $options;
    }
}
