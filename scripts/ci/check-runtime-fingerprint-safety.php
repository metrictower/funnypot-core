#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Runtime fingerprint-safety CI gate (the render-corpus companion of check-fingerprint-safety.php).
 *
 * The static gate scans the COMPILED artifacts, but a tell can also be assembled at REQUEST time:
 * a fabricated {{fake.*}} cell, a persona value, a taunt/injection block, or a behavior body that
 * only exists once rendered. This gate renders the whole corpus with INERT fixed captures across a
 * seed spread and scans every rendered body + header, then scans every reachable constant-table
 * string exhaustively (that is where a fabricated cell would spell a signature, regardless of seed),
 * and proves the render is deterministic. Any hit fails the build.
 *
 *   php scripts/ci/check-runtime-fingerprint-safety.php [--denylist=PATH]
 *
 * Captures are FIXED test constants, so reflection is not an oracle here — this is exactly where the
 * capture-reflecting rules the runtime egress guard must skip get their rendered-bytes coverage.
 * --denylist overrides the package denylist (a non-vacuity seam for the gate's own tests).
 */

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Template\DirectiveRenderer;
use Funnypot\Core\Template\TemplateAttackEmulator;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

$denylistPath = null;
foreach (array_slice($argv, 1) as $arg) {
    if (strncmp($arg, '--denylist=', 11) === 0) {
        $denylistPath = substr($arg, 11);
    }
}
if ($denylistPath !== null) {
    if (!is_file($denylistPath)) {
        fwrite(STDERR, "error: --denylist not found: {$denylistPath}\n");
        exit(1);
    }
    $d = require $denylistPath;
    $guard = new FingerprintGuard(
        is_array($d) ? (array) ($d['literals'] ?? []) : [],
        is_array($d) ? (array) ($d['patterns'] ?? []) : []
    );
} else {
    $guard = FingerprintGuard::fromPackage();
}

$compiled = $root . '/resources/compiled';
$seeds = [0, 1, 7, 42, 1337, 65535, 999999, 2147483646];

$leaks = 0;
$renders = 0;

/** Scan one rendered response; report any hit. @param array<string,string|string[]> $headers */
$scan = static function (string $ctx, string $body, array $headers) use ($guard, &$leaks): void {
    $hits = $guard->scanResponse($body, $headers);
    if ($hits !== []) {
        $leaks++;
        fwrite(STDOUT, "::error::runtime fingerprint leak in {$ctx}: " . implode(', ', $hits) . "\n");
    }
};

// Inert synthetic captures covering every capture name the behaviors read (arith/expr/ssti/decoy/
// traversal) plus numeric groups — all fixed constants so a reflecting rule reflects a NON-token.
$captures = [
    '0' => 'probe', '1' => 'probe', '2' => 'probe', '3' => 'probe',
    'user' => 'probe', 'pass' => 'probe', 'marker' => 'probe', 'path' => '/etc/hostname',
    'a' => '21', 'b' => '21', 'expr' => '7*7', 'surface' => '7*7',
    'sum' => '0', 'result' => '0', 'rendered' => '0', 'value' => 'probe',
];

// --- 1. attack rules + param entries -------------------------------------------------------------
$attack = require $compiled . '/funnypot-attack.php';
$param = require $compiled . '/funnypot-param.php';
$paramEntries = [];
foreach ((array) ($param['buckets'] ?? []) as $entries) {
    foreach ((array) $entries as $entry) {
        $paramEntries[] = $entry;
    }
}
$attackEmu = TemplateAttackEmulator::fromPackage([], 4242, str_repeat('k', 48), false, true);
foreach ($seeds as $seed) {
    foreach (array_merge((array) $attack, $paramEntries) as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        try {
            $resp = $attackEmu->renderRule($rule, $captures, $seed, null);
        } catch (\Throwable $e) {
            continue; // render-correctness is not this gate's job; the fingerprint scan is
        }
        if ($resp !== null) {
            $renders++;
            $scan('attack ' . (string) ($rule['id'] ?? '?') . " @{$seed}", $resp->body, $resp->headers);
        }
    }
}

// --- 2. route rules (both visible styles, injection armed) ---------------------------------------
$routeRules = require $compiled . '/funnypot-routes.php';
$set = RouteTemplateSet::fromFile($compiled . '/funnypot-routes.php');
$beacon = ['beacon' => 'https://beacon.example.test/confirm?t=' . str_repeat('a', 40)];
$routeEmu = new RouteTemplateEmulator($set, new DirectiveRenderer(7), true, $beacon);
foreach ($seeds as $seed) {
    foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
        foreach ((array) $routeRules as $rule) {
            if (!is_array($rule)) {
                continue;
            }
            $bundle = syntheticBundle($rule);
            if ($bundle === null) {
                continue;
            }
            try {
                $resp = $routeEmu->render($bundle, $style, $seed);
            } catch (\Throwable $e) {
                continue;
            }
            if ($resp !== null) {
                $renders++;
                $scan('route ' . (string) ($rule['id'] ?? '?') . " @{$seed}:{$style}", $resp->body, $resp->headers);
            }
        }
    }
}

// --- 3. exhaustive constant-table scan -----------------------------------------------------------
// Every string reachable from these classes' constants (private included), flattened recursively —
// the tables every directive, persona and decoy body draws from. Seed-independent, so it covers
// every table entry regardless of which seed would pick it.
$classes = [
    'Funnypot\\Core\\Support\\Fake\\FakeSecrets',
    'Funnypot\\Core\\Support\\Fake\\FakePeople',
    'Funnypot\\Core\\Support\\Fake\\FakeRecords',
    'Funnypot\\Core\\Support\\PersonaIdentity',
    'Funnypot\\Core\\Synthesis\\SynthScaffold',
    'Funnypot\\Core\\Behavior\\DecoyTables',
    'Funnypot\\Core\\Response\\InjectionPayloads',
    'Funnypot\\Core\\Ai\\ChatFloor',
    'Funnypot\\Core\\Attack\\AttackBodies',
    'Funnypot\\Core\\Support\\Chrome\\PageSlots',
    'Funnypot\\Core\\Support\\SurfaceGraph',
    'Funnypot\\Core\\Attack\\CannedData',
];
$classesScanned = 0;
$tableStrings = 0;
foreach ($classes as $cls) {
    if (!class_exists($cls)) {
        fwrite(STDERR, "error: constant-table class missing: {$cls}\n");
        exit(1);
    }
    $classesScanned++;
    $consts = (new ReflectionClass($cls))->getConstants();
    foreach (flattenStrings($consts) as $keyPath => $text) {
        $tableStrings++;
        $hits = $guard->scan($text);
        if ($hits !== []) {
            $leaks++;
            fwrite(STDOUT, "::error::runtime fingerprint leak in const {$cls}::{$keyPath}: " . implode(', ', $hits) . "\n");
        }
    }
}

// --- 4. determinism: the rendered corpus must be a pure function of its seed ----------------------
// Render seed 7 twice and compare a hash over the bodies + authored headers (Set-Cookie carries a
// per-request random value and X-Request-Id is stamped later, so both are excluded).
$h1 = renderHash($attackEmu, (array) $attack, $paramEntries, $routeEmu, (array) $routeRules, $captures, 7);
$h2 = renderHash($attackEmu, (array) $attack, $paramEntries, $routeEmu, (array) $routeRules, $captures, 7);
if ($h1 !== $h2) {
    fwrite(STDERR, "FAIL: rendered corpus is not deterministic at seed 7 ({$h1} != {$h2}).\n");
    exit(1);
}

if ($leaks > 0) {
    fwrite(STDERR, "FAIL: {$leaks} runtime fingerprint leak(s) across {$renders} renders + {$tableStrings} constant strings.\n");
    exit(1);
}

fwrite(STDOUT, "OK: {$renders} runtime renders + {$tableStrings} constant strings across {$classesScanned} classes carry no upstream-detector signature.\n");
exit(0);

/**
 * A bundle findRule() resolves back to this route rule: template_needle matches on pid/t, else pid,
 * else a body word. null when the rule exposes no selector (nothing to render through the set).
 *
 * @param array<string,mixed> $rule
 * @return array<string,mixed>|null
 */
function syntheticBundle(array $rule): ?array
{
    $match = (array) ($rule['match'] ?? []);
    $needles = array_map('strval', (array) ($match['template_needle'] ?? []));
    if ($needles !== []) {
        return ['pid' => $needles[0], 't' => [$needles[0]], 's' => 200, 'bw' => []];
    }
    $pids = array_map('strval', (array) ($match['pid'] ?? []));
    if ($pids !== []) {
        return ['pid' => $pids[0], 't' => [], 's' => 200, 'bw' => []];
    }
    $words = array_map('strval', (array) ($match['body_word_contains'] ?? []));
    if ($words !== []) {
        return ['pid' => 'runtime-gate', 't' => [], 's' => 200, 'bw' => [$words[0]]];
    }

    return null;
}

/**
 * Flatten a constants tree to keyPath => string. Non-strings (ints/bools) are skipped.
 *
 * @param array<int|string,mixed> $node
 * @return array<string,string>
 */
function flattenStrings(array $node, string $prefix = ''): array
{
    $out = [];
    foreach ($node as $key => $value) {
        $path = $prefix === '' ? (string) $key : $prefix . '.' . (string) $key;
        if (is_string($value)) {
            $out[$path] = $value;
        } elseif (is_array($value)) {
            $out += flattenStrings($value, $path);
        }
    }

    return $out;
}

/**
 * A stable hash over the whole rendered corpus at one seed — bodies + authored headers, with the
 * per-request-random Set-Cookie excluded — used to assert determinism.
 *
 * @param array<int,mixed> $attack
 * @param array<int,mixed> $paramEntries
 * @param array<int,mixed> $routeRules
 * @param array<int|string,string> $captures
 */
function renderHash(
    TemplateAttackEmulator $attackEmu,
    array $attack,
    array $paramEntries,
    RouteTemplateEmulator $routeEmu,
    array $routeRules,
    array $captures,
    int $seed
): string {
    $acc = '';
    foreach (array_merge($attack, $paramEntries) as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        try {
            $resp = $attackEmu->renderRule($rule, $captures, $seed, null);
        } catch (\Throwable $e) {
            continue;
        }
        if ($resp !== null) {
            $acc .= '|A:' . (string) ($rule['id'] ?? '?') . ':' . $resp->body . serializeHeaders($resp->headers);
        }
    }
    foreach ($routeRules as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        $bundle = syntheticBundle($rule);
        if ($bundle === null) {
            continue;
        }
        try {
            $resp = $routeEmu->render($bundle, Style::REALISTIC, $seed);
        } catch (\Throwable $e) {
            continue;
        }
        if ($resp !== null) {
            $acc .= '|R:' . (string) ($rule['id'] ?? '?') . ':' . $resp->body;
        }
    }

    return hash('sha256', $acc);
}

/** @param array<string,string|string[]> $headers */
function serializeHeaders(array $headers): string
{
    $out = '';
    foreach ($headers as $name => $value) {
        if ($name === 'Set-Cookie' || $name === 'X-Request-Id') {
            continue;
        }
        $out .= ';' . $name . '=' . (is_array($value) ? implode(',', $value) : $value);
    }

    return $out;
}
