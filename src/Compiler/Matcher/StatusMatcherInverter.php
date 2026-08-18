<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * Inverts a `status` matcher block (match.go `MatchStatusCode`).
 *
 * Status is OR-only and exact: the response matches if its single status code is any
 * of the listed codes. We record the allowed set; the plan later collapses it to one
 * line (a response has exactly one status). A negative status matcher forbids the set.
 */
final class StatusMatcherInverter
{
    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        $codes = $m['status'] ?? [];
        if (!is_array($codes)) {
            $codes = [$codes];
        }

        $set = [];
        foreach ($codes as $c) {
            if (is_int($c) || (is_string($c) && ctype_digit($c))) {
                $set[] = (int) $c;
            }
        }
        $set = array_values(array_unique($set));
        if ($set === []) {
            return MatcherResult::out('status-empty');
        }

        $r = MatcherResult::in();
        if (!empty($m['negative'])) {
            $r->statusForbidden = $set;
        } else {
            $r->statusAllowed = $set;
        }

        return $r;
    }
}
