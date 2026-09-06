#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Fingerprint-safety CI gate.
 *
 * Fails the build if any SERVED string leaf of a compiled artifact carries an upstream-detector
 * signature (OWASP_CRS / ModSecurity / libinjection / a bare CRS rule id / a scanner name / an
 * OAST callback domain / paranoia-level …). Such a string reaching a served response would let a
 * scanner classify the reply as canned — the exact leak the deception design exists to prevent.
 *
 *   php scripts/ci/check-fingerprint-safety.php [--index=PATH ...]
 *
 * The gate is scan-by-default: ServedStringWalker enumerates EVERY served string leaf of each
 * artifact and only an explicit skip-list (matcher/identifier fields) is pruned, so a new served
 * field is covered the moment it appears — no hand-enumerated rule shapes to fall behind. With no
 * --index, the compiled attack, route AND param served-response artifacts plus the nuclei index
 * and the flat routes-index under resources/compiled/ are scanned (every surface where emulator
 * content lands). The denylist is resources/fingerprint-denylist.php (tracked, append-only).
 */

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Rules\ServedStringWalker;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

// An index passed EXPLICITLY (via --index=) is a hard requirement: a missing path or a
// non-array require means the gate is misconfigured, so it must fail — never fail open by
// skipping. The built-in default set is best-effort (is_file-filtered); the $scanned backstop
// below still catches a default set that scans nothing.
$explicit = false;
$indexes = [];
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--index=', 8) === 0) {
        $indexes[] = substr($arg, 8);
        $explicit = true;
    }
}
if (!$explicit) {
    $indexes = array_values(array_filter([
        $root . '/resources/compiled/funnypot-attack.php',
        $root . '/resources/compiled/funnypot-routes.php',
        $root . '/resources/compiled/funnypot-param.php',
        $root . '/resources/compiled/nuclei-index.full.php',
        $root . '/resources/compiled/funnypot-routes-index.php',
    ], 'is_file'));
}

$guard = FingerprintGuard::fromPackage();
$walker = new ServedStringWalker();
$leaks = 0;
$totalLeaves = 0;
$artifacts = 0;

foreach ($indexes as $index) {
    if (!is_file($index)) {
        if ($explicit) {
            fwrite(STDERR, "error: --index not found: {$index}\n");
            exit(1);
        }
        fwrite(STDERR, "warning: index not found, skipping: {$index}\n");
        continue;
    }
    $artifact = require $index;
    if (!is_array($artifact)) {
        if ($explicit) {
            fwrite(STDERR, "error: --index did not return an array: {$index}\n");
            exit(1);
        }
        continue;
    }

    $leaves = $walker->artifactLeaves($artifact, basename($index));
    $artifacts++;
    $count = count($leaves);
    $totalLeaves += $count;

    // Per-artifact leaf floor: a walker regression that suddenly enumerates NOTHING must not exit
    // 0. Every real artifact has served leaves, so zero is a bug, not a clean bill.
    if ($count === 0) {
        fwrite(STDERR, "error: no served leaves found in {$index} — walker/shape regression.\n");
        exit(1);
    }

    foreach ($leaves as $path => $text) {
        $hits = $guard->scan($text);
        if ($hits !== []) {
            $leaks++;
            fwrite(STDOUT, "::error file={$index}::fingerprint leak at {$path}: " . implode(', ', $hits) . "\n");
        }
    }
}

if ($artifacts === 0) {
    fwrite(STDERR, "error: no compiled artifacts scanned — gate misconfigured.\n");
    exit(1);
}

// Advisory, non-gating: a stale skip entry (never encountered) or a new top-level shape neither
// known-served nor skip-listed is worth a look, but neither weakens the scan — every non-skip leaf
// was scanned above regardless.
$unused = $walker->unusedSkips();
if ($unused !== []) {
    fwrite(STDOUT, 'note: skip-list entries not exercised this run: ' . implode(', ', $unused) . "\n");
}
$unknown = $walker->unknownKeys();
if ($unknown !== []) {
    fwrite(STDOUT, 'note: top-level keys neither known-served nor skip-listed (review the skip-list): '
        . implode(', ', $unknown) . "\n");
}

if ($leaks > 0) {
    fwrite(STDERR, "FAIL: {$leaks} fingerprint leak(s) across {$totalLeaves} served leaves.\n");
    exit(1);
}

fwrite(STDOUT, "OK: {$totalLeaves} served leaves across {$artifacts} artifact(s) carry no upstream-detector signature.\n");
exit(0);
