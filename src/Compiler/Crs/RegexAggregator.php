<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Crs;

/**
 * Folds many CRS detection patterns of one attack class into a single broadened regex
 * alternation — the funnypot posture is one response archetype per class, so the match
 * side must collapse to one condition, never one template per CRS rule id.
 *
 * The combined pattern is compiled with the same `~`-delimited, case-insensitive settings
 * TemplateAttackEmulator uses at runtime, so every transform here keeps it valid under that
 * delimiter:
 *  - a literal `~` is escaped (it is the funnypot delimiter);
 *  - a leading inline `(?i)` is stripped (funnypot already forces the `i` flag; a mid-pattern
 *    global flag would otherwise leak across every other branch of the alternation);
 *  - each source is wrapped in a non-capturing group so top-level anchors/alternation in one
 *    source can't bleed into the next;
 *  - the whole pattern is prefixed with `(?J)` so duplicate named groups across sources
 *    (common in CRS) don't fail compilation.
 *
 * Patterns carrying a numeric backreference are refused (returned as unusable): once sources
 * are concatenated the global group numbering shifts, so a `\1` would silently bind to the
 * wrong group. Those rules are dropped and audited, never combined blind.
 *
 * A whole class's alternation can still exceed PCRE's compiled-pattern limit (CRS's RCE
 * corpus is enormous). build() therefore enforces a byte budget and then trims from the tail
 * until the result compiles — callers order the higher-signal @rx branches first so the
 * @pmFromFile literals are dropped first.
 */
final class RegexAggregator
{
    /**
     * Normalise one source regex into a combinable branch. Returns null when the pattern
     * can't be safely combined (backreference) or doesn't compile on its own.
     */
    public function prepare(string $pattern): ?string
    {
        if ($this->hasBackreference($pattern)) {
            return null;
        }
        $branch = $this->stripLeadingCaseFlag($pattern);
        $branch = $this->escapeDelimiter($branch);

        if (@preg_match('~(?J)(?:' . $branch . ')~i', '') === false) {
            return null;
        }

        return $branch;
    }

    /** Escaped literal branch for a @pmFromFile phrase (a plain substring match). */
    public function literal(string $phrase): string
    {
        return preg_quote($phrase, '~');
    }

    /**
     * Combine ordered branches into one alternation, bounded by $maxBytes and guaranteed to
     * compile. Trims from the tail (least-preferred branches) on either overflow or a PCRE
     * compile failure.
     *
     * @param string[] $branches insertion order = preference (keep-first)
     * @return array{regex:string|null,included:int} included = how many branches survived
     */
    public function build(array $branches, int $maxBytes): array
    {
        $kept = [];
        $len = strlen('(?J)(?:)');
        foreach ($branches as $branch) {
            $add = strlen($branch) + strlen('(?:)|');
            if ($kept !== [] && $len + $add > $maxBytes) {
                break;
            }
            $kept[] = $branch;
            $len += $add;
        }

        while ($kept !== []) {
            $regex = $this->assemble($kept);
            if (@preg_match('~' . $regex . '~i', '') !== false) {
                return ['regex' => $regex, 'included' => count($kept)];
            }
            array_pop($kept);
        }

        return ['regex' => null, 'included' => 0];
    }

    /** @param string[] $branches */
    private function assemble(array $branches): string
    {
        $wrapped = array_map(static function (string $b): string {
            return '(?:' . $b . ')';
        }, $branches);

        return '(?J)(?:' . implode('|', $wrapped) . ')';
    }

    private function stripLeadingCaseFlag(string $pattern): string
    {
        return (string) preg_replace('/^\(\?i\)/', '', $pattern);
    }

    /** Escape every `~` not already escaped (odd run of preceding backslashes ⇒ already escaped). */
    private function escapeDelimiter(string $pattern): string
    {
        return (string) preg_replace_callback('/(\\\\*)~/', static function (array $m): string {
            $slashes = $m[1];

            return strlen($slashes) % 2 === 1 ? $slashes . '~' : $slashes . '\~';
        }, $pattern);
    }

    private function hasBackreference(string $pattern): bool
    {
        // \1..\9 with an even number of preceding backslashes (so the digit escape is live),
        // or a named backreference (\k<name>, \k'name', \k{name}, (?P=name)).
        if (preg_match('/(?<!\\\\)(?:\\\\\\\\)*\\\\[1-9]/', $pattern) === 1) {
            return true;
        }

        return preg_match('/\\\\k[<\'{]|\(\?P=/', $pattern) === 1;
    }
}
