<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Compiler\Matcher\MatcherResult;

/**
 * Conjunction of two constraint sets — used both for dsl `&&` inside one expression and
 * for `matchers-condition: and` across matcher blocks. Returns an OUT result when the
 * two are jointly unsatisfiable (contradictory status sets or incompatible sizes),
 * which is part of screen B6.
 */
final class ConstraintMerge
{
    public static function and(MatcherResult $a, MatcherResult $b): MatcherResult
    {
        if (!$a->ok) {
            return $a;
        }
        if (!$b->ok) {
            return $b;
        }

        $r = MatcherResult::in();
        $r->bodyWords = array_merge($a->bodyWords, $b->bodyWords);
        $r->headerWords = array_merge($a->headerWords, $b->headerWords);
        $r->forbidden = array_merge($a->forbidden, $b->forbidden);
        $r->headerForbidden = array_merge($a->headerForbidden, $b->headerForbidden);
        $r->regexWitness = array_merge($a->regexWitness, $b->regexWitness);
        $r->typedHeader = self::mergeTypedHeaders($a->typedHeader, $b->typedHeader);
        $r->statusForbidden = array_values(array_unique(array_merge($a->statusForbidden, $b->statusForbidden)));
        $r->wholeBodyExclusive = $a->wholeBodyExclusive || $b->wholeBodyExclusive;

        // Allowed status: null means "unconstrained", so it adopts the other side.
        // Two constrained sets intersect; an empty intersection is a contradiction.
        if ($a->statusAllowed === null) {
            $r->statusAllowed = $b->statusAllowed;
        } elseif ($b->statusAllowed === null) {
            $r->statusAllowed = $a->statusAllowed;
        } else {
            $inter = array_values(array_intersect($a->statusAllowed, $b->statusAllowed));
            if ($inter === []) {
                return MatcherResult::out('b6:status-contradiction');
            }
            $r->statusAllowed = $inter;
        }

        $size = self::combineSize($a->size, $b->size);
        if ($size === false) {
            return MatcherResult::out('b6:size-contradiction');
        }
        $r->size = $size;

        return $r;
    }

    /**
     * Union two typed-header maps (canonical name → required substrings). Both sides'
     * substrings must appear in the same header's value, which one emitted value satisfies.
     *
     * @param array<string,string[]> $a
     * @param array<string,string[]> $b
     * @return array<string,string[]>
     */
    private static function mergeTypedHeaders(array $a, array $b): array
    {
        foreach ($b as $name => $subs) {
            $existing = $a[$name] ?? [];
            foreach ($subs as $s) {
                if (!in_array($s, $existing, true)) {
                    $existing[] = $s;
                }
            }
            $a[$name] = $existing;
        }

        return $a;
    }

    /**
     * Intersect two body-length constraints, shared with the merge's compatibility check.
     *
     * @param array{op:string,n:int}|null $a
     * @param array{op:string,n:int}|null $b
     * @return array{op:string,n:int}|null|false false on contradiction
     */
    public static function combineSize($a, $b)
    {
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }

        // eq dominates: both eq must be equal; eq must satisfy the other's bound.
        if ($a['op'] === 'eq' && $b['op'] === 'eq') {
            return $a['n'] === $b['n'] ? $a : false;
        }
        if ($a['op'] === 'eq') {
            return self::eqSatisfies($a['n'], $b) ? $a : false;
        }
        if ($b['op'] === 'eq') {
            return self::eqSatisfies($b['n'], $a) ? $b : false;
        }

        // Two inequalities: keep the tighter, reject disjoint bands.
        $min = null;
        $max = null;
        foreach ([$a, $b] as $c) {
            if ($c['op'] === 'min') {
                $min = $min === null ? $c['n'] : max($min, $c['n']);
            } elseif ($c['op'] === 'max') {
                $max = $max === null ? $c['n'] : min($max, $c['n']);
            }
        }
        if ($min !== null && $max !== null) {
            if ($min > $max) {
                return false;
            }

            // Represent the band by its lower bound; exact width is a synth concern.
            return ['op' => 'min', 'n' => $min];
        }

        return $min !== null ? ['op' => 'min', 'n' => $min] : ['op' => 'max', 'n' => $max];
    }

    /**
     * @param array{op:string,n:int} $bound
     */
    private static function eqSatisfies(int $n, array $bound): bool
    {
        if ($bound['op'] === 'min') {
            return $n >= $bound['n'];
        }
        if ($bound['op'] === 'max') {
            return $n <= $bound['n'];
        }

        return $n === $bound['n'];
    }
}
