#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Fingerprint-safety CI gate.
 *
 * Fails the build if any compiled attack-response body or header carries an upstream-detector
 * signature (OWASP_CRS / ModSecurity / libinjection / a bare CRS rule id / paranoia-level …).
 * Such a string reaching a served response would let a scanner classify the reply as canned —
 * the exact leak the deception design exists to prevent. Runs after the correctness tests and
 * before the PR step in update-crs.yml / update-templates.yml, so a leak blocks the PR.
 *
 *   php scripts/ci/check-fingerprint-safety.php [--index=PATH ...]
 *
 * With no --index, every compiled attack artifact under resources/compiled/ is scanned.
 * The denylist is resources/fingerprint-denylist.php (tracked, append-only).
 */

use Funnypot\Compiler\Crs\FingerprintGuard;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

$indexes = [];
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--index=', 8) === 0) {
        $indexes[] = substr($arg, 8);
    }
}
if ($indexes === []) {
    $indexes = array_values(array_filter([
        $root . '/resources/compiled/funnypot-attack.php',
    ], 'is_file'));
}

$guard = FingerprintGuard::fromPackage();
$leaks = 0;
$scanned = 0;

foreach ($indexes as $index) {
    if (!is_file($index)) {
        fwrite(STDERR, "warning: index not found, skipping: {$index}\n");
        continue;
    }
    $rules = require $index;
    if (!is_array($rules)) {
        continue;
    }
    foreach ($rules as $rule) {
        $scanned++;
        $id = (string) ($rule['id'] ?? '?');
        $response = $rule['response'] ?? [];

        $texts = [(string) ($response['body'] ?? '')];
        foreach ((array) ($response['headers'] ?? []) as $name => $value) {
            $texts[] = (string) $name;
            $texts[] = (string) $value;
        }
        foreach ($texts as $text) {
            $hits = $guard->scan($text);
            if ($hits !== []) {
                $leaks++;
                fwrite(STDOUT, "::error file={$index}::fingerprint leak in '{$id}': " . implode(', ', $hits) . "\n");
            }
        }
    }
}

if ($leaks > 0) {
    fwrite(STDERR, "FAIL: {$leaks} fingerprint leak(s) across {$scanned} compiled response(s).\n");
    exit(1);
}

fwrite(STDOUT, "OK: {$scanned} compiled response(s) carry no upstream-detector signature.\n");
exit(0);
