<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Matcher;

/**
 * Generates strings that a simple regular expression matches, offline.
 *
 * This is a deliberately small recursive generator over a SAFE subset of regex
 * (literals, common escapes, character classes, groups, alternation, bounded
 * quantifiers). It bails to null on anything it does not fully understand
 * (lookaround, backreferences, word boundaries, unicode classes, unbounded nesting).
 *
 * generate() emits ONE canonical witness (the fixed-first representative). generateMenu()
 * (FP-0280) emits that canonical PLUS up to MENU_K-1 alternate witnesses of the same pattern,
 * so a deploy can serve a DIFFERENT-but-equally-valid witness per compiled slot and the
 * fleet stops sharing one constant body byte. Each variable choice point (alternation branch,
 * dot/class/escape representative, repetition count) becomes a pool the variant chooser draws
 * from; variant zero always draws option zero, so generateMenu(core)[0] === generate(core)
 * byte-for-byte. The choice stream is a pure function of (core, variant) and is pinned by
 * fixture tests — a change to it is an artifact migration.
 *
 * The generated witness is only a CANDIDATE: {@see RegexWitnessGenerator} re-validates every
 * one with PHP `preg_match` against the original pattern and screens it for fingerprint tells.
 * Go's RE2 and PCRE can diverge (e.g. POSIX classes, `\z` vs `$`), so when the two disagree the
 * matcher/alternate is dropped rather than shipped.
 */
final class RegexWitness
{
    private const MAX_LEN = 512;
    private const MAX_DEPTH = 40;

    /** Menu size: the canonical plus up to three alternates. */
    public const MENU_K = 4;

    /** Highest variant tried when filling a menu. Variant 0 is the canonical. */
    private const MAX_VARIANT = 16;

    /** The dot / word-escape representative pool, in the exact order generate() has always used. */
    private const DOT_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

    /** @var string */
    private $s;

    /** @var int */
    private $i = 0;

    /** @var int */
    private $n;

    /** @var bool */
    private $failed = false;

    /** @var int the variant being generated; 0 is the canonical (always option 0). */
    private $variant = 0;

    /** @var int choice ordinal — advances only past a genuine multi-option choice. */
    private $q = 0;

    private function __construct(string $pattern)
    {
        $this->s = $pattern;
        $this->n = strlen($pattern);
    }

    /**
     * Return a witness for the pattern's CORE (anchors already stripped by the caller),
     * or null if the pattern is outside the safe subset. Byte-identical to the historical
     * fixed-first generator (it is generateMenu()'s variant-zero pass).
     */
    public static function generate(string $core): ?string
    {
        if ($core === '' || strlen($core) > self::MAX_LEN) {
            return null;
        }
        $g = new self($core);
        $out = $g->parseAlternation(0);
        if ($g->failed || $g->i !== $g->n) {
            return null;
        }

        return $out;
    }

    /**
     * Return up to $k distinct, non-empty witnesses for $core — the canonical first, then
     * alternates from variants 1..MAX_VARIANT. Empty, duplicate and canonical-equal alternates
     * are dropped. Returns [] when the canonical itself cannot be generated. Pure function of
     * ($core, $k): no deploy material, clock or randomness enters.
     *
     * @return list<string> canonical at index 0
     */
    public static function generateMenu(string $core, int $k): array
    {
        if ($core === '' || strlen($core) > self::MAX_LEN) {
            return [];
        }
        $k = max(1, min($k, self::MENU_K));

        $menu = [];
        $seen = [];
        for ($variant = 0; $variant <= self::MAX_VARIANT; $variant++) {
            $g = new self($core);
            $g->variant = $variant;
            $w = $g->parseAlternation(0);
            if ($g->failed || $g->i !== $g->n) {
                if ($variant === 0) {
                    return []; // canonical ungeneratable ⇒ no menu
                }
                continue;
            }
            if ($variant === 0) {
                if ($w === '') {
                    return []; // empty canonical ⇒ no menu
                }
                $menu[] = $w;
                $seen[$w] = true;
                continue;
            }
            if ($w === '' || isset($seen[$w])) {
                continue; // empty / duplicate / canonical-equal alternate
            }
            $menu[] = $w;
            $seen[$w] = true;
            if (count($menu) >= $k) {
                break;
            }
        }

        return $menu;
    }

    /**
     * Pick option 0 for the canonical, or a variant-derived option for an alternate. A
     * single-option point (count <= 1) consumes no choice window; every genuine multi-option
     * choice reads two hex digits at offset (q % 32)*2 of the block-floor(q/32) digest of
     * (core, variant), reduces that byte modulo the option count, then advances q.
     */
    private function chooseIndex(int $count): int
    {
        if ($count <= 1 || $this->variant === 0) {
            return 0;
        }
        $block = intdiv($this->q, 32);
        $offset = ($this->q % 32) * 2;
        $digest = hash('sha256', $this->s . '|' . $this->variant . '|' . $block);
        $byte = (int) hexdec(substr($digest, $offset, 2));
        $this->q++;

        return $byte % $count;
    }

    /**
     * @param list<string> $options
     */
    private function pick(array $options): string
    {
        if ($options === []) {
            return $this->fail();
        }

        return $options[$this->chooseIndex(count($options))];
    }

    private function fail(): string
    {
        $this->failed = true;

        return '';
    }

    private function parseAlternation(int $depth): string
    {
        // Alternation branches are a choice pool in source order. Variant zero takes the first
        // branch (byte-identical to the historical generator); a later variant may take another.
        // Every branch is parsed either way, so a malformed non-first branch still fails the pass.
        $branches = [$this->parseSequence($depth)];
        if ($this->failed) {
            return '';
        }
        while ($this->i < $this->n && $this->s[$this->i] === '|') {
            $this->i++; // consume '|'
            $branches[] = $this->parseSequence($depth);
            if ($this->failed) {
                return '';
            }
        }

        return $branches[$this->chooseIndex(count($branches))];
    }

    private function parseSequence(int $depth): string
    {
        if ($depth > self::MAX_DEPTH) {
            return $this->fail();
        }

        $out = '';
        while ($this->i < $this->n) {
            $c = $this->s[$this->i];
            if ($c === '|' || $c === ')') {
                break;
            }

            $atom = $this->parseAtom($depth);
            if ($this->failed) {
                return '';
            }

            $out .= $this->applyQuantifier($atom);
            if ($this->failed) {
                return '';
            }
        }

        return $out;
    }

    private function parseAtom(int $depth): string
    {
        $c = $this->s[$this->i];

        switch ($c) {
            case '(':
                return $this->parseGroup($depth);
            case '[':
                return $this->parseClass();
            case '.':
                $this->i++;

                return $this->pick(str_split(self::DOT_ALPHABET));
            case '\\':
                return $this->parseEscape();
            case '^':
            case '$':
                // A stray anchor inside the core is beyond this simple engine.
                return $this->fail();
            case '*':
            case '+':
            case '?':
                // Quantifier with nothing to bind.
                return $this->fail();
            default:
                $this->i++;

                return $c;
        }
    }

    private function parseGroup(int $depth): string
    {
        $this->i++; // consume '('
        // Reject anything but a plain or non-capturing / inline-flag group.
        if ($this->i < $this->n && $this->s[$this->i] === '?') {
            // Allowed: (?:  and inline flag groups (?i) (?i:  (?m) (?s) ...
            $j = $this->i + 1;
            $flags = '';
            while ($j < $this->n && strpos('imsxU', $this->s[$j]) !== false) {
                $flags .= $this->s[$j];
                $j++;
            }
            if ($j < $this->n && $this->s[$j] === ':') {
                $this->i = $j + 1; // non-capturing / flagged group body
            } elseif ($j < $this->n && $this->s[$j] === ')') {
                // Bare inline flags like (?i) — consume and emit nothing.
                $this->i = $j + 1;

                return '';
            } else {
                // Lookaround, named groups, atomic, conditionals — unsupported.
                return $this->fail();
            }
        }

        $body = $this->parseAlternation($depth + 1);
        if ($this->failed) {
            return '';
        }
        if ($this->i >= $this->n || $this->s[$this->i] !== ')') {
            return $this->fail();
        }
        $this->i++; // consume ')'

        return $body;
    }

    private function parseClass(): string
    {
        $this->i++; // consume '['
        $negated = false;
        if ($this->i < $this->n && $this->s[$this->i] === '^') {
            $negated = true;
            $this->i++;
        }

        $members = [];
        $ranges = [];
        $first = true;
        while ($this->i < $this->n && ($this->s[$this->i] !== ']' || $first)) {
            $first = false;
            $ch = $this->s[$this->i];
            if ($ch === '\\') {
                $esc = $this->classEscape();
                if ($this->failed) {
                    return '';
                }
                $members[] = $esc;
                $this->i += 2;

                continue;
            }
            // range a-z
            if ($this->i + 2 < $this->n && $this->s[$this->i + 1] === '-' && $this->s[$this->i + 2] !== ']') {
                $lo = $ch;
                $hi = $this->s[$this->i + 2];
                $ranges[] = [$lo, $hi];
                $this->i += 3;

                continue;
            }
            $members[] = $ch;
            $this->i++;
        }

        if ($this->i >= $this->n || $this->s[$this->i] !== ']') {
            return $this->fail();
        }
        $this->i++; // consume ']'

        $pool = $negated
            ? $this->negatedClassPool($members, $ranges)
            : $this->positiveClassPool($members, $ranges);

        return $this->pick($pool);
    }

    /**
     * A positive class pool: the historical representative first (members[0], else the first
     * range's low byte), then explicit members in source order, then per range its low byte,
     * high byte and floor midpoint. De-duplicated without sorting, so option 0 is unchanged.
     *
     * @param list<string>          $members
     * @param list<array{0:string,1:string}> $ranges
     * @return list<string>
     */
    private function positiveClassPool(array $members, array $ranges): array
    {
        $pool = [];
        if ($members !== []) {
            $pool[] = $members[0];
        } elseif ($ranges !== []) {
            $pool[] = $ranges[0][0];
        }
        foreach ($members as $m) {
            $pool[] = $m;
        }
        foreach ($ranges as [$lo, $hi]) {
            $pool[] = $lo;
            $pool[] = $hi;
            $pool[] = chr(intdiv(ord($lo) + ord($hi), 2));
        }

        return $this->dedupe($pool);
    }

    /**
     * A negated class pool: the printable alphabet filtered against every excluded member and
     * range, in alphabet order — so option 0 is the first non-excluded char (unchanged).
     *
     * @param list<string>          $members
     * @param list<array{0:string,1:string}> $ranges
     * @return list<string>
     */
    private function negatedClassPool(array $members, array $ranges): array
    {
        $excluded = [];
        foreach ($members as $m) {
            $excluded[$m] = true;
        }
        $pool = [];
        foreach (str_split(self::DOT_ALPHABET) as $cand) {
            if (isset($excluded[$cand])) {
                continue;
            }
            $inRange = false;
            foreach ($ranges as [$lo, $hi]) {
                if ($cand >= $lo && $cand <= $hi) {
                    $inRange = true;
                    break;
                }
            }
            if (!$inRange) {
                $pool[] = $cand;
            }
        }

        return $pool;
    }

    /**
     * @param list<string> $values
     * @return list<string>
     */
    private function dedupe(array $values): array
    {
        $seen = [];
        $out = [];
        foreach ($values as $v) {
            if (!isset($seen[$v])) {
                $seen[$v] = true;
                $out[] = $v;
            }
        }

        return $out;
    }

    /** Escape inside a character class — returns the representative char. */
    private function classEscape(): string
    {
        $next = $this->s[$this->i + 1] ?? '';
        if ($next === '') {
            return $this->fail();
        }

        return $this->escapeChar($next);
    }

    private function parseEscape(): string
    {
        $this->i++; // consume '\'
        if ($this->i >= $this->n) {
            return $this->fail();
        }
        $c = $this->s[$this->i];

        // Reject constructs we cannot honor.
        if (ctype_digit($c)) {
            return $this->fail(); // backreference
        }
        if ($c === 'b' || $c === 'B' || $c === 'A' || $c === 'z' || $c === 'Z' || $c === 'G' || $c === 'p' || $c === 'P' || $c === 'k') {
            return $this->fail();
        }

        if ($c === 'x') {
            // \xHH
            $hex = substr($this->s, $this->i + 1, 2);
            if (strlen($hex) === 2 && ctype_xdigit($hex)) {
                $this->i += 3;

                return chr((int) hexdec($hex));
            }

            return $this->fail();
        }

        $this->i++;

        // A digit/word escape as a standalone atom is a choice pool; every other escape keeps
        // its single fixed representative and consumes no choice window.
        if ($c === 'd') {
            return $this->pick(str_split('0123456789'));
        }
        if ($c === 'w') {
            return $this->pick(str_split(self::DOT_ALPHABET . '_'));
        }

        return $this->escapeChar($c);
    }

    private function escapeChar(string $c): string
    {
        switch ($c) {
            case 'd':
                return '0';
            case 'w':
                return 'a';
            case 's':
                return ' ';
            case 'D':
            case 'W':
                return 'x';
            case 'S':
                return 'x';
            case 'n':
                return "\n";
            case 'r':
                return "\r";
            case 't':
                return "\t";
            case 'f':
                return "\f";
            case 'v':
                return "\v";
            case '0':
                return "\0";
            default:
                // Escaped literal metacharacter (\. \/ \+ \( …).
                return $c;
        }
    }

    private function applyQuantifier(string $atom): string
    {
        if ($this->i >= $this->n) {
            return $atom;
        }
        $q = $this->s[$this->i];

        if ($q === '*' || $q === '+' || $q === '?') {
            $this->i++;
            $this->consumeLazyPossessive();

            // `?` may also drop the atom (count 0); `*`/`+` add extra copies. Option 0 keeps one
            // copy, so the canonical is byte-identical to the historical one-copy behavior.
            $counts = ($q === '?') ? [1, 0] : [1, 2, 3];
            $count = $counts[$this->chooseIndex(count($counts))];
            if ($count === 0) {
                return '';
            }
            if ($count * max(1, strlen($atom)) > self::MAX_LEN) {
                return $this->fail();
            }

            return str_repeat($atom, $count);
        }

        if ($q === '{') {
            return $this->applyBraceQuantifier($atom);
        }

        return $atom;
    }

    private function applyBraceQuantifier(string $atom): string
    {
        // {n} {n,} {n,m}
        $close = strpos($this->s, '}', $this->i);
        if ($close === false) {
            return $atom; // literal '{'
        }
        $inner = substr($this->s, $this->i + 1, $close - $this->i - 1);
        if (!preg_match('/^(\d+)(,(\d*)?)?$/', $inner, $mm)) {
            return $atom; // literal '{...}'
        }
        $this->i = $close + 1;
        $this->consumeLazyPossessive();

        $min = (int) $mm[1];
        $base = max($min, 1);
        // Option 0 is the historical count max(min,1). A bounded/open range adds the next valid
        // counts through min(maximum, minimum + 2); an exact {n} offers no extra count.
        $counts = [$base];
        if (isset($mm[2]) && $mm[2] !== '') {
            $maxBound = (isset($mm[3]) && $mm[3] !== '') ? (int) $mm[3] : null;
            $upper = $maxBound === null ? $min + 2 : min($maxBound, $min + 2);
            for ($v = $base + 1; $v <= $upper; $v++) {
                $counts[] = $v;
            }
        }
        $counts = $this->dedupeCounts($counts);

        $count = $counts[$this->chooseIndex(count($counts))];
        // Guard against pathological expansion.
        if ($count * max(1, strlen($atom)) > self::MAX_LEN) {
            return $this->fail();
        }

        return str_repeat($atom, $count);
    }

    /**
     * @param list<int> $counts
     * @return list<int>
     */
    private function dedupeCounts(array $counts): array
    {
        $seen = [];
        $out = [];
        foreach ($counts as $c) {
            if (!isset($seen[$c])) {
                $seen[$c] = true;
                $out[] = $c;
            }
        }

        return $out;
    }

    private function consumeLazyPossessive(): void
    {
        if ($this->i < $this->n && ($this->s[$this->i] === '?' || $this->s[$this->i] === '+')) {
            $this->i++;
        }
    }
}
