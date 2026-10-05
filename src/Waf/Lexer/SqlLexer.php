<?php

declare(strict_types=1);

namespace Funnypot\Core\Waf\Lexer;

/**
 * A streaming, character-scanning SQL lexer (FP-0436 spike, promoted to FP-0426). Single linear pass over the input
 * (substr/ord only — NO `preg_*` over the surface), so it is O(n) and ReDoS-free BY CONSTRUCTION: this
 * is the core advantage over the PCRE alternation the CRS pipeline trims at 45KB. Detection-only — the
 * token stream is read by SqlNormalizer (FP-0426) to canonicalise the surface and never re-emitted on the wire (invariant #1).
 *
 * MySQL comment semantics are reproduced to match the SHIPPED SafeComparison canonicaliser (pinned by
 * SafeComparisonCharacterizationTest), so the lexer can be the single canonicalisation source:
 *  - `/* … *\/` plain inline comment folds to nothing;
 *  - `/*! … *\/` versioned comment is UNWRAPPED — its inner bytes are tokenised live (a sqlmap
 *    versionedkeywords tamper still exposes the keywords);
 *  - `--` is a line comment ONLY when followed by whitespace/EOL (so `10--5` stays arithmetic);
 *  - `#` is always a line comment to end-of-line.
 *
 * Bounded: at most MAX_BYTES of input and MAX_TOKENS tokens are processed (the caller already clips the
 * surface; this is defence-in-depth), and versioned-comment unwrapping recurses at most MAX_DEPTH deep.
 *
 * PHP 7.3-safe: no typed properties, arrow fns, `match`, `str_contains`, or named arguments.
 */
final class SqlLexer
{
    public const MAX_BYTES = 32768;
    public const MAX_TOKENS = 4096;
    private const MAX_DEPTH = 8;

    /**
     * Tokenise $input into a list of ['t' => int(SqlToken::T_*), 'v' => string] in source order.
     * Whitespace and comments are folded away (never emitted); every other lexeme yields one token.
     *
     * @return array<int,array{t:int,v:string}>
     */
    public function tokenize(string $input): array
    {
        if (strlen($input) > self::MAX_BYTES) {
            $input = substr($input, 0, self::MAX_BYTES);
        }
        $out = [];
        $this->scan($input, $out, 0);

        return $out;
    }

    /**
     * @param array<int,array{t:int,v:string}> $out
     */
    private function scan(string $s, array &$out, int $depth): void
    {
        $n = strlen($s);
        $i = 0;
        while ($i < $n) {
            if (count($out) >= self::MAX_TOKENS) {
                return;
            }
            $c = $s[$i];
            $o = ord($c);

            // Whitespace (space, tab, NL, CR, VT, FF) — fold.
            if ($o === 32 || ($o >= 9 && $o <= 13)) {
                $i++;
                continue;
            }

            // Block comment /* … */ (plain fold) or /*! … */ (versioned unwrap).
            if ($c === '/' && $i + 1 < $n && $s[$i + 1] === '*') {
                $close = strpos($s, '*/', $i + 2);
                if ($close === false) {
                    return; // unterminated — fold the remainder (bounded; no literal tail tokenised)
                }
                if ($i + 2 < $n && $s[$i + 2] === '!' && $depth < self::MAX_DEPTH) {
                    // Versioned: skip `/*!` + optional 5-6 version digits, tokenise the inner bytes live.
                    $innerStart = $i + 3;
                    while ($innerStart < $close && $innerStart < $i + 9 && ctype_digit($s[$innerStart])) {
                        $innerStart++;
                    }
                    $inner = substr($s, $innerStart, $close - $innerStart);
                    $this->scan($inner, $out, $depth + 1);
                }
                $i = $close + 2;
                continue;
            }

            // Line comment: -- only when followed by whitespace/EOL (MySQL), else two operators.
            if ($c === '-' && $i + 1 < $n && $s[$i + 1] === '-') {
                $after = $i + 2;
                $isComment = $after >= $n;
                if (!$isComment) {
                    $oa = ord($s[$after]);
                    $isComment = ($oa === 32 || ($oa >= 9 && $oa <= 13));
                }
                if ($isComment) {
                    $nl = strpos($s, "\n", $after);
                    $i = $nl === false ? $n : $nl + 1;
                    continue;
                }
                // not a comment — fall through to operator handling for this single '-'
            }

            // Line comment: # to end-of-line (always).
            if ($c === '#') {
                $nl = strpos($s, "\n", $i + 1);
                $i = $nl === false ? $n : $nl + 1;
                continue;
            }

            // String literal '…' or "…" with '' / "" doubling and \ escaping.
            if ($c === "'" || $c === '"') {
                $i = $this->readString($s, $i, $n, $c, $out);
                continue;
            }

            // Backtick-quoted identifier.
            if ($c === '`') {
                $end = strpos($s, '`', $i + 1);
                $end = $end === false ? $n : $end;
                $out[] = ['t' => SqlToken::T_IDENT, 'v' => substr($s, $i + 1, $end - $i - 1)];
                $i = $end < $n ? $end + 1 : $n;
                continue;
            }

            // Numeric literal: hex 0x.., binary 0b.., x'..'/b'.. handled as string already; decimals.
            if ($o >= 48 && $o <= 57) {
                $i = $this->readNumber($s, $i, $n, $out);
                continue;
            }

            // Identifier / keyword: [A-Za-z_][A-Za-z0-9_]* (maximal run ⇒ intact-boundary invariant).
            if ($o === 95 || ($o >= 65 && $o <= 90) || ($o >= 97 && $o <= 122)) {
                $i = $this->readWord($s, $i, $n, $out);
                continue;
            }

            // Operators and punctuation.
            $i = $this->readOperator($s, $i, $n, $c, $out);
        }
    }

    /** @param array<int,array{t:int,v:string}> $out */
    private function readString(string $s, int $i, int $n, string $q, array &$out): int
    {
        $j = $i + 1;
        while ($j < $n) {
            $ch = $s[$j];
            if ($ch === '\\' && $j + 1 < $n) {
                $j += 2; // backslash escape
                continue;
            }
            if ($ch === $q) {
                if ($j + 1 < $n && $s[$j + 1] === $q) {
                    $j += 2; // doubled quote '' / "" — stays inside the string
                    continue;
                }
                $j++; // closing quote
                break;
            }
            $j++;
        }
        $out[] = ['t' => SqlToken::T_STRING, 'v' => substr($s, $i, $j - $i)];

        return $j;
    }

    /** @param array<int,array{t:int,v:string}> $out */
    private function readNumber(string $s, int $i, int $n, array &$out): int
    {
        $j = $i;
        if ($s[$j] === '0' && $j + 1 < $n && ($s[$j + 1] === 'x' || $s[$j + 1] === 'X' || $s[$j + 1] === 'b' || $s[$j + 1] === 'B')) {
            $j += 2;
            while ($j < $n && ctype_alnum($s[$j])) {
                $j++;
            }
            $out[] = ['t' => SqlToken::T_NUMBER, 'v' => substr($s, $i, $j - $i)];

            return $j;
        }
        while ($j < $n) {
            $ch = $s[$j];
            if (ctype_digit($ch) || $ch === '.' || $ch === 'e' || $ch === 'E'
                || (($ch === '+' || $ch === '-') && $j > $i && ($s[$j - 1] === 'e' || $s[$j - 1] === 'E'))) {
                $j++;
                continue;
            }
            break;
        }
        $out[] = ['t' => SqlToken::T_NUMBER, 'v' => substr($s, $i, $j - $i)];

        return $j;
    }

    /** @param array<int,array{t:int,v:string}> $out */
    private function readWord(string $s, int $i, int $n, array &$out): int
    {
        $j = $i;
        while ($j < $n) {
            $o = ord($s[$j]);
            if ($o === 95 || ($o >= 48 && $o <= 57) || ($o >= 65 && $o <= 90) || ($o >= 97 && $o <= 122)) {
                $j++;
                continue;
            }
            break;
        }
        $word = substr($s, $i, $j - $i);
        $lower = strtolower($word);
        if (isset(SqlToken::FUNCTIONS[$lower])) {
            $out[] = ['t' => SqlToken::T_FUNC, 'v' => $word];
        } elseif (isset(SqlToken::KEYWORDS[$lower])) {
            $out[] = ['t' => SqlToken::KEYWORDS[$lower], 'v' => $word];
        } else {
            $out[] = ['t' => SqlToken::T_IDENT, 'v' => $word];
        }

        return $j;
    }

    /** @param array<int,array{t:int,v:string}> $out */
    private function readOperator(string $s, int $i, int $n, string $c, array &$out): int
    {
        $next = $i + 1 < $n ? $s[$i + 1] : '';
        switch ($c) {
            case '=':
                $out[] = ['t' => SqlToken::T_CMP, 'v' => '='];

                return $i + 1;
            case '<':
                if ($next === '=' || $next === '>') {
                    $out[] = ['t' => SqlToken::T_CMP, 'v' => '<' . $next];

                    return $i + 2;
                }
                $out[] = ['t' => SqlToken::T_CMP, 'v' => '<'];

                return $i + 1;
            case '>':
                if ($next === '=') {
                    $out[] = ['t' => SqlToken::T_CMP, 'v' => '>='];

                    return $i + 2;
                }
                $out[] = ['t' => SqlToken::T_CMP, 'v' => '>'];

                return $i + 1;
            case '!':
                if ($next === '=') {
                    $out[] = ['t' => SqlToken::T_CMP, 'v' => '!='];

                    return $i + 2;
                }
                $out[] = ['t' => SqlToken::T_PUNCT, 'v' => '!'];

                return $i + 1;
            case '|':
                if ($next === '|') {
                    $out[] = ['t' => SqlToken::T_CONCAT, 'v' => '||'];

                    return $i + 2;
                }
                $out[] = ['t' => SqlToken::T_OP, 'v' => '|'];

                return $i + 1;
            case '(':
                $out[] = ['t' => SqlToken::T_LPAREN, 'v' => '('];

                return $i + 1;
            case ')':
                $out[] = ['t' => SqlToken::T_RPAREN, 'v' => ')'];

                return $i + 1;
            case ',':
                $out[] = ['t' => SqlToken::T_COMMA, 'v' => ','];

                return $i + 1;
            case ';':
                $out[] = ['t' => SqlToken::T_SEMI, 'v' => ';'];

                return $i + 1;
            case '*':
                $out[] = ['t' => SqlToken::T_STAR, 'v' => '*'];

                return $i + 1;
            case '+':
            case '-':
            case '/':
            case '%':
            case '^':
            case '&':
            case '~':
                $out[] = ['t' => SqlToken::T_OP, 'v' => $c];

                return $i + 1;
            default:
                $out[] = ['t' => SqlToken::T_PUNCT, 'v' => $c];

                return $i + 1;
        }
    }
}
