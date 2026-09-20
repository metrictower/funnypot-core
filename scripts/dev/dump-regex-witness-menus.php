#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * FP-0280 developer/operator audit stream. Runs the REAL compiler over a nuclei-templates http
 * directory with an audit observer wired into the shared witness generator, so it sees every
 * canonical/menu pair from BOTH the @regex matcher and the DSL regex() path AFTER lowercasing and
 * PCRE validation — without maintaining a second YAML/DSL parser and without writing any artifact.
 *
 * Each distinct (pattern, canonical, menu) row is emitted as one base64-safe JSONL line so arbitrary
 * witness bytes (from \xHH etc.) survive a line-based pipe:
 *
 *     {"p":"<b64 pattern>","c":"<b64 canonical>","a":["<b64 alt>", ...]}
 *
 * Pipe it into the Go RE2 oracle, which fails on any RE2 compile error, canonical miss or alternate
 * miss:
 *
 *     php scripts/dev/dump-regex-witness-menus.php /path/to/nuclei-templates/http |
 *       go run scripts/dev/re2-witness-check/main.go
 *
 * This reads the corpus only; it compiles into memory and writes nothing to the tree. Corpus fetch,
 * Docker, ssh and package installs are NOT part of this run — it is an operator/CI step.
 */

use Funnypot\Core\Compiler\Classifier;
use Funnypot\Core\Compiler\Compiler;
use Funnypot\Core\Compiler\Matcher\RegexWitnessGenerator;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

$dir = $argv[1] ?? '';
if ($dir === '' || !is_dir($dir)) {
    fwrite(STDERR, "usage: dump-regex-witness-menus.php <nuclei-templates/http dir>\n");
    exit(2);
}

/** @var array<string,array{p:string,c:string,a:string[]}> $rows deduped by (pattern|canonical|menu) */
$rows = [];

$observer = static function (string $pattern, string $canonical, array $alternates) use (&$rows): void {
    $key = $pattern . "\x00" . $canonical . "\x00" . implode("\x00", $alternates);
    if (isset($rows[$key])) {
        return;
    }
    $rows[$key] = [
        'p' => base64_encode($pattern),
        'c' => base64_encode($canonical),
        'a' => array_map('base64_encode', $alternates),
    ];
};

$generator = new RegexWitnessGenerator(null, $observer);
$classifier = new Classifier(null, $generator);
$compiler = new Compiler($classifier);

// Compile purely for its observer side effects; the returned artifact is discarded.
$compiler->compile($dir, ['tag' => 'audit', 'sha' => 'audit']);

foreach ($rows as $row) {
    echo json_encode($row, JSON_UNESCAPED_SLASHES), "\n";
}

fwrite(STDERR, 'dumped ' . count($rows) . " distinct pattern/menu rows\n");
