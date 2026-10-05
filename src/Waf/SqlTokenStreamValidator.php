<?php

declare(strict_types=1);

namespace Funnypot\Core\Waf;

use Funnypot\Core\Waf\Lexer\SqlLexer;
use Funnypot\Core\Waf\Lexer\SqlToken;

/**
 * FP-0436 Phase 1: an O(n) deterministic recogniser of high-confidence SQL-injection SUBSTRING-grammar
 * productions over the SqlLexer token stream. It does NOT parse whole statements and does NOT decide
 * truth — it recognises attack-class FRAGMENTS so the honeypot attack tier can serve the existing
 * deception archetype on obfuscated payloads the trimmed @rx alternation 404s (comment-split /
 * versioned / hex / concat). Detection-only: nothing it reads is ever re-emitted (invariant #1).
 *
 * FP discipline is STRUCTURAL, not a boundary rule alone (the keywords `and`/`or`/`union`/`;` all occur
 * intact in ordinary prose, JSON, headers). Each production requires the full fragment shape, and the
 * tautology production in particular requires STATIC operands (literal=literal, or an identical-
 * identifier self-comparison) so an ordinary field filter (`col = 1`) or prose (`tax = total`) does NOT
 * match. This is what earns the FP budget (gate G1).
 *
 * Phase 1 is STANDALONE — no pipeline wiring. Phase 2 maps a hit to the existing attack-crs-sqli
 * archetype behind a fail-closed wrapper (a fault → no match → plain 404, never a 500).
 *
 * PHP 7.3-safe.
 */
final class SqlTokenStreamValidator
{
    public const P_TAUTOLOGY = 'tautology';
    public const P_UNION = 'union-select';
    public const P_STACKED = 'stacked-query';
    public const P_FUNCTION = 'injection-function';

    /** @var SqlLexer */
    private $lexer;

    public function __construct(?SqlLexer $lexer = null)
    {
        $this->lexer = $lexer ?: new SqlLexer();
    }

    /**
     * The production that matched (one of the P_* constants), or null for no match. Returns the FIRST
     * production found scanning left-to-right; callers that only need a boolean use isAttack().
     */
    public function classify(string $input): ?string
    {
        $tokens = $this->lexer->tokenize($input);
        $n = count($tokens);

        for ($i = 0; $i < $n; $i++) {
            $t = $tokens[$i]['t'];

            if (($t === SqlToken::T_OR || $t === SqlToken::T_AND) && $this->matchTautology($tokens, $n, $i + 1)) {
                return self::P_TAUTOLOGY;
            }
            if ($t === SqlToken::T_UNION && $this->matchUnionSelect($tokens, $n, $i + 1)) {
                return self::P_UNION;
            }
            if ($t === SqlToken::T_SEMI && $this->matchStacked($tokens, $n, $i + 1)) {
                return self::P_STACKED;
            }
            if ($t === SqlToken::T_FUNC && $i + 1 < $n && $tokens[$i + 1]['t'] === SqlToken::T_LPAREN) {
                return self::P_FUNCTION;
            }
        }

        return null;
    }

    public function isAttack(string $input): bool
    {
        return $this->classify($input) !== null;
    }

    /**
     * Tautology after a boolean connective: `[(] operand [)] <cmp> [(] operand [)]`, where the two
     * operands are BOTH static literals (number/string) or an identical-identifier self-comparison
     * (`a = a`). A column-vs-value filter (`col = 1`) and prose (`tax = total`) are deliberately NOT a
     * match — that is the false-positive firewall.
     *
     * @param array<int,array{t:int,v:string}> $tokens
     */
    private function matchTautology(array $tokens, int $n, int $i): bool
    {
        $i = $this->skip($tokens, $n, $i, SqlToken::T_LPAREN);
        if ($i >= $n || !$this->isOperand($tokens[$i]['t'])) {
            return false;
        }
        $left = $tokens[$i];
        $i = $this->skip($tokens, $n, $i + 1, SqlToken::T_RPAREN);
        if ($i >= $n || $tokens[$i]['t'] !== SqlToken::T_CMP) {
            return false;
        }
        $i = $this->skip($tokens, $n, $i + 1, SqlToken::T_LPAREN);
        if ($i >= $n || !$this->isOperand($tokens[$i]['t'])) {
            return false;
        }
        $right = $tokens[$i];

        $leftLiteral = $left['t'] === SqlToken::T_NUMBER || $left['t'] === SqlToken::T_STRING;
        $rightLiteral = $right['t'] === SqlToken::T_NUMBER || $right['t'] === SqlToken::T_STRING;
        if ($leftLiteral && $rightLiteral) {
            return true; // 1=1, 'a'='a', 1<2, 0x31=0x31
        }
        // identical-identifier self-comparison: a=a (case-insensitive bareword), the classic column
        // tautology. Different identifiers (col=other) are an ordinary filter — not a match.
        if ($left['t'] === SqlToken::T_IDENT && $right['t'] === SqlToken::T_IDENT) {
            return strcasecmp($left['v'], $right['v']) === 0;
        }

        return false;
    }

    /**
     * `UNION [ALL] SELECT <sql-ish select list>` — an intact SELECT must follow UNION (optionally via
     * ALL), then a select-list head that is clearly SQL: `*`, a literal, a function, a subquery `(`, or
     * an identifier THAT IS CONTINUED by a `,` or `FROM` within a short window. A lone identifier with
     * no continuation is prose (`trade union select committee`) and declines; `union jack`/`union
     * catalog` decline (no SELECT); a bare UNION never matches.
     *
     * @param array<int,array{t:int,v:string}> $tokens
     */
    private function matchUnionSelect(array $tokens, int $n, int $i): bool
    {
        if ($i < $n && $tokens[$i]['t'] === SqlToken::T_ALL) {
            $i++;
        }
        if ($i >= $n || $tokens[$i]['t'] !== SqlToken::T_SELECT) {
            return false;
        }
        $i++;
        if ($i >= $n) {
            return false;
        }
        $head = $tokens[$i]['t'];
        if ($head === SqlToken::T_STAR || $head === SqlToken::T_NUMBER || $head === SqlToken::T_STRING
            || $head === SqlToken::T_FUNC || $head === SqlToken::T_LPAREN) {
            return true;
        }
        if ($head === SqlToken::T_IDENT) {
            // Require a column-list / FROM continuation so a prose "select <word>" isn't a match.
            return $this->hasWithin($tokens, $n, $i + 1, 4, [SqlToken::T_COMMA, SqlToken::T_FROM]);
        }

        return false;
    }

    /**
     * Stacked query: a `;` anchored to an intact statement-initial SQL verb WITH its characteristic
     * follow-keyword, so benign imperative prose (`; update the docs`, `; delete later`, `; drop it`)
     * declines. SELECT-based stacking is covered by the UNION production, so a lone `; select …` is not
     * matched here (too prose-prone via a later FROM).
     *
     * @param array<int,array{t:int,v:string}> $tokens
     */
    private function matchStacked(array $tokens, int $n, int $i): bool
    {
        if ($i >= $n) {
            return false;
        }
        switch ($tokens[$i]['t']) {
            case SqlToken::T_DROP:
            case SqlToken::T_CREATE:
            case SqlToken::T_ALTER:
                return $this->hasWithin($tokens, $n, $i + 1, 2, [SqlToken::T_TABLE]);
            case SqlToken::T_INSERT:
                return $this->hasWithin($tokens, $n, $i + 1, 1, [SqlToken::T_INTO]);
            case SqlToken::T_DELETE:
                return $this->hasWithin($tokens, $n, $i + 1, 1, [SqlToken::T_FROM]);
            case SqlToken::T_UPDATE:
                return $this->hasWithin($tokens, $n, $i + 1, 3, [SqlToken::T_SET]);
            default:
                return false;
        }
    }

    /**
     * True if any token in [$i, $i+$window) has a type in $types. Bounded (no unbounded scan) — keeps
     * the validator O(n) with a small constant per anchor.
     *
     * @param array<int,array{t:int,v:string}> $tokens
     * @param int[]                            $types
     */
    private function hasWithin(array $tokens, int $n, int $i, int $window, array $types): bool
    {
        $end = min($n, $i + $window);
        for (; $i < $end; $i++) {
            if (in_array($tokens[$i]['t'], $types, true)) {
                return true;
            }
        }

        return false;
    }

    private function isOperand(int $t): bool
    {
        return $t === SqlToken::T_NUMBER || $t === SqlToken::T_STRING || $t === SqlToken::T_IDENT;
    }

    /**
     * Advance past a single optional token of type $type (used for one layer of parens around an
     * operand). Bounded, no loop — a real tautology needs at most one paren layer per side here.
     *
     * @param array<int,array{t:int,v:string}> $tokens
     */
    private function skip(array $tokens, int $n, int $i, int $type): int
    {
        if ($i < $n && $tokens[$i]['t'] === $type) {
            return $i + 1;
        }

        return $i;
    }
}
