<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

/**
 * The single merge law for canonical/menu witness pairs (FP-0280). One frozen rx slot may represent
 * several source patterns that collapsed to the same canonical string; its served alternate set must
 * satisfy EVERY such pattern, so equal canonicals INTERSECT their menus rather than the first writer
 * winning. Used at all three current collapse points — ConstraintMerge::and(), Classifier::finalize()
 * and Bundle::add() — so no boundary can silently keep-first or concatenate.
 *
 * Rules (spec §4):
 *   1. a new canonical (below the optional cap) is added with its normalized alternate list;
 *   2. an EXISTING canonical replaces its menu with array_intersect(existing, incoming) in existing
 *      order — a missing/empty incoming menu makes the intersection empty;
 *   3. the cap bounds only NEW canonicals; an equal canonical arriving after the cap is still
 *      intersected (so a late collision still narrows a full menu);
 *   4. output is two equal-length, numerically-indexed aligned arrays (rx, rxm).
 *
 * The merge is pure and idempotent. Alternate normalization drops empty, canonical-equal and duplicate
 * values while preserving first-seen order.
 */
final class RegexWitnessSet
{
    private function __construct()
    {
    }

    /**
     * Merge two aligned pair-sets into normalized aligned arrays.
     *
     * @param string[]            $rxA
     * @param array<int,string[]> $rxmA aligned with $rxA
     * @param string[]            $rxB
     * @param array<int,string[]> $rxmB aligned with $rxB
     * @param int|null            $cap  max distinct canonicals (null = unbounded)
     * @return array{0: string[], 1: array<int,string[]>} [rx, rxm] aligned
     */
    public static function merge(array $rxA, array $rxmA, array $rxB, array $rxmB, ?int $cap = null): array
    {
        $order = [];   // list<string> canonicals in first-seen order
        $menus = [];   // canonical => list<string> alternates
        self::absorb($order, $menus, $rxA, $rxmA, $cap);
        self::absorb($order, $menus, $rxB, $rxmB, $cap);

        return self::flatten($order, $menus);
    }

    /**
     * Normalize a single aligned pair-set (dedup canonicals, intersect collisions, drop bad alternates).
     *
     * @param string[]            $rx
     * @param array<int,string[]> $rxm aligned with $rx
     * @param int|null            $cap
     * @return array{0: string[], 1: array<int,string[]>}
     */
    public static function normalize(array $rx, array $rxm, ?int $cap = null): array
    {
        $order = [];
        $menus = [];
        self::absorb($order, $menus, $rx, $rxm, $cap);

        return self::flatten($order, $menus);
    }

    /**
     * @param list<string>          $order
     * @param array<string,string[]> $menus
     * @param string[]              $rx
     * @param array<int,string[]>   $rxm
     */
    private static function absorb(array &$order, array &$menus, array $rx, array $rxm, ?int $cap): void
    {
        $rx = array_values($rx);
        foreach ($rx as $i => $canonical) {
            $canonical = (string) $canonical;
            $incoming = self::cleanMenu($canonical, $rxm[$i] ?? []);
            if (!array_key_exists($canonical, $menus)) {
                if ($cap !== null && count($order) >= $cap) {
                    continue; // cap bounds only NEW canonicals
                }
                $order[] = $canonical;
                $menus[$canonical] = $incoming;
                continue;
            }
            // Equal canonical: intersect in existing order (still applies past the cap).
            $menus[$canonical] = array_values(array_intersect($menus[$canonical], $incoming));
        }
    }

    /**
     * Drop empty, canonical-equal and duplicate alternates, preserving first-seen order.
     *
     * @param mixed $menu
     * @return list<string>
     */
    private static function cleanMenu(string $canonical, $menu): array
    {
        if (!is_array($menu)) {
            return [];
        }
        $seen = [];
        $out = [];
        foreach ($menu as $alt) {
            $alt = (string) $alt;
            if ($alt === '' || $alt === $canonical || isset($seen[$alt])) {
                continue;
            }
            $seen[$alt] = true;
            $out[] = $alt;
        }

        return $out;
    }

    /**
     * @param list<string>           $order
     * @param array<string,string[]> $menus
     * @return array{0: string[], 1: array<int,string[]>}
     */
    private static function flatten(array $order, array $menus): array
    {
        $rx = [];
        $rxm = [];
        foreach ($order as $canonical) {
            $rx[] = $canonical;
            $rxm[] = $menus[$canonical];
        }

        return [$rx, $rxm];
    }
}
