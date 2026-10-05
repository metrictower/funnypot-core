<?php

declare(strict_types=1);

namespace Funnypot\Core\Waf;

use Funnypot\Core\Waf\Lexer\SqlLexer;
use Funnypot\Core\Waf\Lexer\SqlToken;

/**
 * FP-0426: a SQL canonicaliser that neutralises sqlmap lexical tamper scripts so the EXISTING
 * detection (the 20-sqli-differential param route) matches an obfuscated payload the same way it
 * matches the plain form. It does NOT classify and emits NO verdict — it rewrites a surface string to
 * a canonical form; the existing, already-FP-tuned regex/SafeComparison path decides. The only new
 * false-positive risk is normalisation-INDUCED (a benign value whose canonical form the existing path
 * then matches), which is what the FP-0426 G-gate measures as an induced delta.
 *
 * Built on the FP-0436 SqlLexer, so comment folding (plain `/* *\/` stripped, `/*! *\/` versioned-
 * unwrapped, `--` only before whitespace/EOL, `#`), whitespace collapse, and keyword case-folding are
 * inherited. On top it applies exactly the STRUCTURAL rewrites the tamper set needs that the lexer does
 * not already cover:
 *   - `LIKE`                → `=`   (sqlmap `equaltolike`)
 *   - `X BETWEEN lo AND hi` → `X = lo` (sqlmap `between`)
 * The `castprefix` (`cast(1 as decimal) AND 1=1`) and `odbcbrace` (`{x !0}*1 AND 1=1`) tampers need NO
 * rewrite: the trailing `AND 1=1` is exposed to the boundary-anchored differential regex once comments/
 * whitespace are folded, so the cast/brace noise before it is harmless. Hex/binary/URL decoding is NOT
 * re-implemented here — BoundedInspection's decoder already folds those before the branch sees the
 * surface (FP-0426 would only duplicate + risk divergence).
 *
 * FAIL-CLOSED: any lexer/normalisation fault returns the INPUT UNCHANGED (never throws, never a 5xx),
 * so the consumer degrades to today's raw-surface behaviour (security invariant #2).
 *
 * PHP 7.3-safe (no typed properties / arrow fns / match / str_contains / named args).
 */
final class SqlNormalizer
{
    /** @var SqlLexer */
    private $lexer;

    public function __construct(?SqlLexer $lexer = null)
    {
        $this->lexer = $lexer ?: new SqlLexer();
    }

    /**
     * Return the canonical form of $input (comments folded, whitespace single-spaced, keywords lower-
     * cased, LIKE/BETWEEN rewritten), or $input unchanged on any fault / empty lex.
     */
    public function normalize(string $input): string
    {
        try {
            $tokens = $this->lexer->tokenize($input);
            if ($tokens === []) {
                return $input;
            }
            $out = $this->emit($tokens);

            return $out === '' ? $input : $out;
        } catch (\Throwable $e) {
            return $input;
        }
    }

    /**
     * Re-emit the token stream as a single-space-joined canonical string with the structural rewrites.
     * String literals are emitted verbatim (never rewritten inside quotes).
     *
     * @param array<int,array{t:int,v:string}> $tokens
     */
    private function emit(array $tokens): string
    {
        $n = count($tokens);
        $parts = [];
        for ($i = 0; $i < $n; $i++) {
            $type = $tokens[$i]['t'];
            $v = $tokens[$i]['v'];

            // equaltolike: LIKE behaves as `=` for the tautology surface.
            if ($type === SqlToken::T_LIKE) {
                $parts[] = '=';
                continue;
            }

            // between: `X BETWEEN lo AND hi` -> `X = lo` (X already emitted). Degrades gracefully if the
            // trailing `AND hi` is absent.
            if ($type === SqlToken::T_IDENT && strcasecmp($v, 'between') === 0) {
                $parts[] = '=';
                if ($i + 1 < $n) {
                    $parts[] = $tokens[$i + 1]['v'];
                    $i++;
                }
                if ($i + 1 < $n && $tokens[$i + 1]['t'] === SqlToken::T_AND) {
                    $i++;                       // skip AND
                    if ($i + 1 < $n) {
                        $i++;                   // skip hi
                    }
                }
                continue;
            }

            // ODBC brace `{ … }` noise — drop the braces, keep the inner tokens.
            if ($type === SqlToken::T_PUNCT && ($v === '{' || $v === '}')) {
                continue;
            }

            if (self::isKeyword($type)) {
                $parts[] = strtolower($v);
                continue;
            }

            $parts[] = $v;
        }

        return implode(' ', $parts);
    }

    /** True for a case-folded SQL keyword token (its canonical emission is the lower-cased lexeme). */
    private static function isKeyword(int $type): bool
    {
        return $type >= SqlToken::T_SELECT && $type <= SqlToken::T_SET
            && $type !== SqlToken::T_FUNC; // FUNC keeps its original-case name (a function identifier)
    }
}
