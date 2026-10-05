<?php

declare(strict_types=1);

/**
 * FP-0436 Phase 1 — CLEAN-ROOM SQLi OBFUSCATION-DELTA corpus for the G1 recall floor.
 *
 * These are the payloads the validator must EARN its false-positive budget on: obfuscated SQLi the
 * trimmed @rx / @pmFromFile alternation misses — comment-split keywords, MySQL versioned comments,
 * hex/binary literals, string concatenation, `--`/`#` terminators, and stacked/UNION/function shapes.
 * BLATANT payloads already caught by the @rx branches at FP floor 1.0 (e.g. a bare `1' OR '1'='1` with
 * app-side quote context, bare `UNION SELECT` with spaces) are intentionally OUT of scope here — the
 * delta is the incremental coverage, not what regex already handles.
 *
 * Authored in-repo from re-derived SQL/obfuscation facts (sqlmap tamper techniques by NAME, not by
 * vendoring sqlmap/libinjection payload files — fingerprint-safety golden rule). Each value is a
 * genuine injection fragment; none is wired to execute anything (detection-only test data).
 *
 * @return array<int,array{label:string,value:string}>
 */
return [
    // comment-split keywords (sqlmap: space2comment / between-keyword comments)
    ['label' => 'comment-split:or', 'value' => '1/**/OR/**/1=1'],
    ['label' => 'comment-split:and', 'value' => '1/**/AND/**/1=1'],
    ['label' => 'comment-split:union', 'value' => '-1/**/UNION/**/SELECT/**/1,2,3'],
    ['label' => 'comment-split:union2', 'value' => '1 UNION/**/SELECT/**/user,pass/**/FROM/**/users'],
    ['label' => 'comment-split:stacked', 'value' => "1;/**/DROP/**/TABLE/**/users"],

    // MySQL versioned conditional comments (sqlmap: versionedkeywords / versionedmorekeywords)
    ['label' => 'versioned:union', 'value' => '-1 /*!50000UNION*/ /*!50000SELECT*/ 1,2,3'],
    ['label' => 'versioned:and', 'value' => '1 /*!AND*/ 1=1'],
    ['label' => 'versioned:or', 'value' => '1/*!50000OR*/1=1'],
    ['label' => 'versioned:select', 'value' => '1 UNION /*!SELECT*/ password FROM users'],

    // hex / binary literals (sqlmap: charencode-adjacent; the @rx store keys on quoted strings)
    ['label' => 'hex:taut-num', 'value' => '1 OR 0x31=0x31'],
    ['label' => 'hex:taut-str', 'value' => '1 OR 0x61=0x61'],
    ['label' => 'hex:union', 'value' => '-1 UNION SELECT 0x41,0x42,0x43'],
    ['label' => 'binary:taut', 'value' => '1 OR 0b1=0b1'],

    // string literal tautologies (balanced quotes — not the app-quote blatant case)
    ['label' => 'str:taut', 'value' => "1 OR 'a'='a'"],
    ['label' => 'str:taut-and', 'value' => "1 AND 'x'='x'"],
    ['label' => 'str:ident-self', 'value' => '1 OR name=name'],

    // newline / tab whitespace tricks (post-decode surface; @rx space classes vary)
    ['label' => 'ws:newline-or', 'value' => "1\nOR\n1=1"],
    ['label' => 'ws:tab-union', 'value' => "-1\tUNION\tSELECT\t1,2"],

    // `--` and `#` terminators (MySQL `-- ` needs trailing space; sqlmap appends the comment)
    ['label' => 'term:dashdash', 'value' => '1 OR 1=1-- -'],
    ['label' => 'term:hash', 'value' => '1 OR 1=1#'],
    ['label' => 'term:dashdash-union', 'value' => '-1 UNION SELECT 1,2,3-- -'],

    // stacked queries (DDL/DML with the characteristic follow-keyword)
    ['label' => 'stacked:drop', 'value' => '1;DROP TABLE users'],
    ['label' => 'stacked:delete', 'value' => '1; DELETE FROM accounts WHERE 1=1'],
    ['label' => 'stacked:insert', 'value' => "1; INSERT INTO logs VALUES ('x')"],
    ['label' => 'stacked:update', 'value' => '1; UPDATE users SET role=0x61646d696e'],
    ['label' => 'stacked:create', 'value' => '1; CREATE TABLE t (id int)'],

    // UNION extraction variants
    ['label' => 'union:all-null', 'value' => '-1 UNION ALL SELECT NULL,NULL,NULL'],
    ['label' => 'union:from', 'value' => '1 UNION SELECT username,password FROM admin_users'],
    ['label' => 'union:count-probe', 'value' => '0 UNION SELECT 1,2,3,4,5'],
    ['label' => 'union:subquery', 'value' => '1 UNION SELECT (SELECT password FROM users LIMIT 1)'],

    // time-/error-based functions
    ['label' => 'func:sleep', 'value' => '1 AND SLEEP(5)'],
    ['label' => 'func:benchmark', 'value' => '1 AND BENCHMARK(5000000,MD5(1))'],
    ['label' => 'func:extractvalue', 'value' => '1 AND EXTRACTVALUE(1,CONCAT(0x7e,0x61))'],
    ['label' => 'func:updatexml', 'value' => '1 AND UPDATEXML(1,CONCAT(0x7e,0x61),1)'],
    ['label' => 'func:pg-sleep', 'value' => "1; SELECT PG_SLEEP(5)"],

    // parenthesised tautology (sqlmap: various)
    ['label' => 'paren:taut', 'value' => '1 OR (1)=(1)'],
    ['label' => 'paren:taut-str', 'value' => "1 OR ('a')=('a')"],

    // mixed-case keywords (the lexer case-folds; @rx case classes can be trimmed)
    ['label' => 'case:union', 'value' => '-1 uNiOn SeLeCt 1,2,3'],
    ['label' => 'case:or', 'value' => '1 Or 1=1'],

    // comparison operator variety
    ['label' => 'cmp:gt', 'value' => '1 OR 2>1'],
    ['label' => 'cmp:neq', 'value' => "1 OR 'a'<>'b'"],
    ['label' => 'cmp:ge', 'value' => '1 OR 5>=5'],
];
