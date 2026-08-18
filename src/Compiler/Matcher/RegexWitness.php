<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * Generates ONE string that a simple regular expression matches, offline.
 *
 * This is a deliberately small recursive generator over a SAFE subset of regex
 * (literals, common escapes, character classes, groups, alternation, bounded
 * quantifiers). It bails to null on anything it does not fully understand
 * (lookaround, backreferences, word boundaries, unicode classes, unbounded nesting).
 *
 * The generated witness is only a CANDIDATE: the caller re-validates it with PHP
 * `preg_match`, and the true correctness gate is the Phase 6 nuclei golden test. Go's
 * RE2 and PCRE can diverge (e.g. POSIX classes, `\z` vs `$`), so when the two disagree
 * the matcher must be folded OUT rather than shipped.
 */
final class RegexWitness
{
    private const MAX_LEN = 512;
    private const MAX_DEPTH = 40;

    private string $s;
    private int $i = 0;
    private int $n;
    private bool $failed = false;

    private function __construct(string $pattern)
    {
        $this->s = $pattern;
        $this->n = strlen($pattern);
    }

    /**
     * Return a witness for the pattern's CORE (anchors already stripped by the caller),
     * or null if the pattern is outside the safe subset.
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

    private function fail(): string
    {
        $this->failed = true;

        return '';
    }

    private function parseAlternation(int $depth): string
    {
        // Take the FIRST branch of a top-level alternation; skip the rest.
        $branch = $this->parseSequence($depth);
        if ($this->failed) {
            return '';
        }
        if ($this->i < $this->n && $this->s[$this->i] === '|') {
            // Consume remaining alternatives without emitting them.
            $this->skipRemainingAlternatives($depth);
        }

        return $branch;
    }

    private function skipRemainingAlternatives(int $depth): void
    {
        while ($this->i < $this->n && $this->s[$this->i] === '|') {
            $this->i++; // consume '|'
            $this->parseSequence($depth); // parse & discard
            if ($this->failed) {
                return;
            }
        }
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

                return 'a';
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

        if (!$negated) {
            if ($members !== []) {
                return $members[0];
            }
            if ($ranges !== []) {
                return $ranges[0][0];
            }

            return $this->fail();
        }

        // Negated: pick a printable char not excluded.
        $excluded = [];
        foreach ($members as $mch) {
            $excluded[$mch] = true;
        }
        foreach (str_split('abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') as $cand) {
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
                return $cand;
            }
        }

        return $this->fail();
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

            // One copy satisfies *, +, and ? alike (and keeps the witness non-empty).
            return $atom;
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
        $count = max($min, 1);
        // Guard against pathological expansion.
        if ($count * max(1, strlen($atom)) > self::MAX_LEN) {
            return $this->fail();
        }

        return str_repeat($atom, $count);
    }

    private function consumeLazyPossessive(): void
    {
        if ($this->i < $this->n && ($this->s[$this->i] === '?' || $this->s[$this->i] === '+')) {
            $this->i++;
        }
    }
}
