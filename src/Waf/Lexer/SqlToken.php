<?php

declare(strict_types=1);

namespace Funnypot\Core\Waf\Lexer;

/**
 * The FROZEN, VERSIONED token enum emitted by SqlLexer (FP-0436 spike, promoted to FP-0426).
 * This is a deliverable contract — FP-0426 (SqlNormalizer delegation) and
 * FP-0437 (lexical-tamper-cycling correlation) bind to these type ids, so their meaning must not shift
 * under an existing id. ADD new ids at the end and bump CONTRACT_VERSION; never renumber.
 *
 * PHP 7.3: a class of int consts (no native enum until 8.1). A token is the pair {type, text} where
 * text is the original lexeme (never re-emitted on the wire — detection only, security invariant #1).
 */
final class SqlToken
{
    /** Bump on any additive change to the id set; never renumber an existing id. */
    public const CONTRACT_VERSION = 1;

    public const T_EOF = 0;
    public const T_NUMBER = 1;   // decimal / float / hex 0x.. / x'..' / b'..' literal (a static operand)
    public const T_STRING = 2;   // single- or double-quoted string literal (a static operand)
    public const T_IDENT = 3;    // a bareword identifier that is NOT a recognised keyword (column, name, prose word)
    public const T_CMP = 4;      // comparison operator: = != <> < > <= >=
    public const T_OP = 5;       // arithmetic/bitwise operator: + - * / % ^ & etc.
    public const T_CONCAT = 6;   // || string-concatenation
    public const T_LPAREN = 7;
    public const T_RPAREN = 8;
    public const T_COMMA = 9;
    public const T_SEMI = 10;    // ; statement separator (stacked-query anchor)
    public const T_STAR = 11;    // * (SELECT * and multiplication both lex here; context disambiguates)
    public const T_PUNCT = 12;   // any other single punctuation char

    // Keyword tokens (an identifier run matched case-insensitively against the keyword set). Kept as
    // distinct ids so the validator state machine switches on them directly.
    public const T_SELECT = 20;
    public const T_UNION = 21;
    public const T_ALL = 22;
    public const T_FROM = 23;
    public const T_WHERE = 24;
    public const T_AND = 25;
    public const T_OR = 26;
    public const T_LIKE = 27;
    public const T_INSERT = 28;
    public const T_UPDATE = 29;
    public const T_DELETE = 30;
    public const T_DROP = 31;
    public const T_CREATE = 32;
    public const T_ALTER = 33;
    public const T_FUNC = 34;    // a recognised dangerous function name (SLEEP/BENCHMARK/EXTRACTVALUE/…)
    public const T_TABLE = 35;   // object keyword after DDL: TABLE/DATABASE/SCHEMA/INDEX/VIEW
    public const T_INTO = 36;    // INSERT INTO
    public const T_SET = 37;     // UPDATE … SET

    /**
     * Keyword lexeme (lower-case) → token id. An identifier run is classified against this map; a miss
     * is T_IDENT (so `reunion` stays one T_IDENT and never yields a T_UNION — the intact-boundary
     * invariant that kills substring-in-word false positives).
     *
     * @var array<string,int>
     */
    public const KEYWORDS = [
        'select' => self::T_SELECT,
        'union' => self::T_UNION,
        'all' => self::T_ALL,
        'from' => self::T_FROM,
        'where' => self::T_WHERE,
        'and' => self::T_AND,
        'or' => self::T_OR,
        'xor' => self::T_OR,   // treated as a boolean connective for the tautology production
        'like' => self::T_LIKE,
        'insert' => self::T_INSERT,
        'update' => self::T_UPDATE,
        'delete' => self::T_DELETE,
        'drop' => self::T_DROP,
        'create' => self::T_CREATE,
        'alter' => self::T_ALTER,
        'truncate' => self::T_DELETE,
        'replace' => self::T_INSERT,
        'table' => self::T_TABLE,
        'database' => self::T_TABLE,
        'schema' => self::T_TABLE,
        'index' => self::T_TABLE,
        'view' => self::T_TABLE,
        'into' => self::T_INTO,
        'set' => self::T_SET,
    ];

    /**
     * Dangerous SQL function names (lower-case) whose `name(` shape is a high-confidence injection
     * signal (time-based / error-based / out-of-band). An identifier in this set is lexed T_FUNC.
     * Coordinate with FP-0431 (which surfaces EXTRACTVALUE/SLEEP/BENCHMARK in Http/Responder) — this
     * set is the lexer-side recogniser, not a second response path.
     *
     * @var array<string,true>
     */
    public const FUNCTIONS = [
        'sleep' => true,
        'benchmark' => true,
        'extractvalue' => true,
        'updatexml' => true,
        'pg_sleep' => true,
        'waitfor' => true,
        'dbms_pipe' => true,
        'load_file' => true,
    ];

    private function __construct()
    {
        // static contract holder; never instantiated
    }
}
