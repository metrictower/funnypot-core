<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Merge = conflict-partition, not blind union (§2). Per route group, color the
 * template plans into compatible persona bundles by graph coloring: place each plan
 * into the first bundle it does not conflict with, else open a new one.
 *
 * Satisfying template A never breaks B — they land in different bundles and exactly one
 * bundle is served per attacker identity, so a response is never Frankensteined.
 */
final class BundlePartitioner
{
    /**
     * @param SatisfyPlan[] $plans
     * @return Bundle[]
     */
    public function partition(array $plans): array
    {
        $ordered = $this->order($plans);

        /** @var Bundle[] $bundles */
        $bundles = [];
        foreach ($ordered as $plan) {
            $placed = false;
            foreach ($bundles as $bundle) {
                if ($this->compatible($bundle, $plan)) {
                    $bundle->add($plan);
                    $placed = true;
                    break;
                }
            }
            if (!$placed) {
                $bundle = new Bundle();
                $bundle->add($plan);
                $bundles[] = $bundle;
            }
        }

        return $bundles;
    }

    /**
     * Stable ordering: 200-ish first, then most-constrained first, so discriminating
     * plans seed bundles before permissive ones.
     *
     * @param SatisfyPlan[] $plans
     * @return SatisfyPlan[]
     */
    private function order(array $plans): array
    {
        $indexed = array_values($plans);
        usort($indexed, static function (SatisfyPlan $a, SatisfyPlan $b): int {
            $sa = ($a->status === null || $a->status === 200) ? 0 : 1;
            $sb = ($b->status === null || $b->status === 200) ? 0 : 1;
            if ($sa !== $sb) {
                return $sa <=> $sb;
            }
            $wa = count($a->bodyWords) + count($a->regexWitness) + count($a->headerWords);
            $wb = count($b->bodyWords) + count($b->regexWitness) + count($b->headerWords);
            if ($wa !== $wb) {
                return $wb <=> $wa; // desc
            }

            return strcmp($a->id, $b->id); // deterministic tie-break
        });

        return $indexed;
    }

    private function compatible(Bundle $bundle, SatisfyPlan $plan): bool
    {
        // 5. whole-body-exclusive plans stand alone.
        if ($plan->wholeBodyExclusive && !$bundle->isEmpty()) {
            return false;
        }
        if ($bundle->wholeBodyExclusive) {
            return false; // bundle already owns the whole body
        }

        // 1. one status line.
        if ($bundle->status !== null && $plan->status !== null && $bundle->status !== $plan->status) {
            return false;
        }

        // 6. product identity.
        if ($bundle->product !== '' && $plan->product !== '' && $bundle->product !== $plan->product) {
            return false;
        }

        // 4. size band.
        if (ConstraintMerge::combineSize($bundle->size, $plan->size) === false) {
            return false;
        }

        // 2 & 3. required-present vs forbidden, both directions and both regions.
        $planBody = array_merge($plan->bodyWords, $plan->regexWitness);
        $bundleBody = array_merge($bundle->bodyWords, $bundle->regexWitness);
        if ($this->substringConflict($planBody, $bundle->forbidden)) {
            return false;
        }
        if ($this->substringConflict($bundleBody, $plan->forbidden)) {
            return false;
        }
        if ($this->substringConflict($plan->headerWords, $bundle->headerForbidden)) {
            return false;
        }
        if ($this->substringConflict($bundle->headerWords, $plan->headerForbidden)) {
            return false;
        }

        return true;
    }

    /**
     * True when any forbidden string is contained in any required string.
     *
     * @param string[] $required
     * @param string[] $forbidden
     */
    private function substringConflict(array $required, array $forbidden): bool
    {
        foreach ($forbidden as $f) {
            if ($f === '') {
                continue;
            }
            foreach ($required as $w) {
                if ($w !== '' && strpos($w, $f) !== false) {
                    return true;
                }
            }
        }

        return false;
    }
}
