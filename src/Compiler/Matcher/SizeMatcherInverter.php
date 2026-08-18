<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * Inverts a `size` matcher block (match.go `MatchSize`).
 *
 * Size is OR-only and exact on the length of the matched part. Pinning the body to an
 * exact length leaves no room for other templates' content, so a size constraint is
 * whole-body-exclusive (A4). The http corpus currently ships no `size:` matchers —
 * exact-size arrives via the dsl `len(body) == N` path — but this keeps the matcher
 * surface complete.
 */
final class SizeMatcherInverter
{
    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        if (!empty($m['negative'])) {
            return MatcherResult::out('size-negative-unsupported');
        }

        $sizes = $m['size'] ?? [];
        if (!is_array($sizes)) {
            $sizes = [$sizes];
        }
        $ints = [];
        foreach ($sizes as $s) {
            if (is_int($s) || (is_string($s) && ctype_digit($s))) {
                $ints[] = (int) $s;
            }
        }
        if ($ints === []) {
            return MatcherResult::out('size-empty');
        }

        $r = MatcherResult::in();
        // Collapse the OR-set to a single exact length (any one satisfies the matcher).
        $r->size = ['op' => 'eq', 'n' => min($ints)];
        $r->wholeBodyExclusive = true;

        return $r;
    }
}
