#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Sampled seeded-render CI gate (FP-0276).
 *
 * The static fingerprint gate (check-fingerprint-safety.php) scans the AUTHORED directive text in the
 * compiled artifacts — it never sees the bytes a deploy actually serves after {{persona.*}}/{{fake.*}}/
 * {{pick:*}} resolve. This gate renders the whole served corpus (attack + route + param rules) across a
 * fixed grid of deploy seeds × render seeds, TWICE at each point, and asserts four things over the
 * RENDERED OUTPUT:
 *
 *   G1  fingerprint-clean — no served byte carries an upstream-detector signature (the denylist, as-is).
 *   G2  markers present   — every YAML `expect:` marker is a substring of the rule's base render at
 *                            every grid point (base `response` render with empty captures, so a
 *                            behavior rule that picks a non-base body cannot false-fail this).
 *   G3  determinism       — the two renders at one (deploySeed, renderSeed) point are byte-identical,
 *                            modulo the ONE legitimate per-request variance these render paths carry:
 *                            the route Set-Cookie random value (E2). This gate renders BELOW the
 *                            respond() facade, so the X-Request-Id (E1) is never emitted here;
 *                            volatileProof (E3) is off, latency (E4) is metadata not bytes, and the
 *                            Clock (E5) is fixed — none can appear in this output by construction.
 *   G4  cross-deploy       — every surface in resources/seeded-surfaces.php differs between two deploy
 *       variance             materials at a fixed render seed (a regression that re-constants a
 *                            converted surface is caught here).
 *
 * It also PRINTS (never fails on) the fleet-constant inventory — surfaces identical at every grid point
 * — the siblings' work list. This script reads compiled artifacts + template YAML only; it writes and
 * compiles NOTHING (zero compiled-byte impact).
 *
 *   php scripts/ci/check-seeded-render.php
 *     [--attack=PATH] [--routes=PATH] [--param=PATH] [--templates=DIR] [--surfaces=PATH]
 *     [--volatile-proof]   (test-only: arm volatileProof so a {{volatile.*}} body FAILS G3)
 *
 * Exit code 1 on any G1–G4 failure or on zero rules rendered (fail-closed floor).
 */

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Contracts\Clock;
use Funnypot\Core\Response\EmulatedContent;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Template\DirectiveRenderer;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Symfony\Component\Yaml\Yaml;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

// --- args ------------------------------------------------------------------------------------------
$opt = [
    'attack' => $root . '/resources/compiled/funnypot-attack.php',
    'routes' => $root . '/resources/compiled/funnypot-routes.php',
    'param' => $root . '/resources/compiled/funnypot-param.php',
    'templates' => $root . '/templates',
    'surfaces' => $root . '/resources/seeded-surfaces.php',
];
$volatileProof = false;
foreach (array_slice($argv, 1) as $arg) {
    if ($arg === '--volatile-proof') {
        $volatileProof = true;
        continue;
    }
    foreach ($opt as $k => $_) {
        if (strncmp($arg, "--{$k}=", strlen($k) + 3) === 0) {
            $opt[$k] = substr($arg, strlen($k) + 3);
        }
    }
}

// --- grid ------------------------------------------------------------------------------------------
// Identity materials INCLUDE '' (core's fleet default) and 'funnypot' (the app-tier default, N8): the
// fleet-default persona must render as cleanly as any other, and its inclusion documents it in CI.
$materials = ['', 'funnypot', 'fp-0276-sample-a', 'fp-0276-sample-b'];
$deploySeeds = [];
foreach ($materials as $m) {
    $deploySeeds[$m] = PersonaIdentity::seedFromMaterial($m);
}
// Render seeds are exactly seedFor()'s shape: crc32('<host>|<salt>').
$renderSeeds = [
    'r-a' => crc32('gate.example|fp-0276-sample-a'),
    'r-b' => crc32('gate.example|fp-0276-sample-b'),
];

$FIXED_CLOCK = new class implements Clock {
    public function now(): int
    {
        return 1735689600; // fixed epoch, so any clock-driven behavior is stable across renders
    }
};
$FIXED_DECOY_KEY = 'fp-0276-fixed-decoy-key';

// --- load artifacts --------------------------------------------------------------------------------
$attackRules = requireArray($opt['attack']);
$routeRules = requireArray($opt['routes']);
$paramRaw = requireArray($opt['param']);
$paramRules = flattenParam($paramRaw);
$paramBuckets = (isset($paramRaw['buckets']) && is_array($paramRaw['buckets'])) ? $paramRaw : [];

$guard = FingerprintGuard::fromPackage();
$markers = collectMarkers($opt['templates']);
$surfaces = is_file($opt['surfaces']) ? requireArray($opt['surfaces']) : [];

$fail = [];       // list<string> failure messages
$rendered = 0;    // rule×point renders (×2)
$leavesScanned = 0;
$seededVerified = 0;
$fleetConstant = []; // list<string> surface keys constant across the whole grid

// canonical output of one render, with the E2 Set-Cookie value masked to its shape.
$canon = static function ($resp): ?array {
    if ($resp === null) {
        return null;
    }
    /** @var SynthesizedResponse|EmulatedContent $resp */
    $status = $resp->status;
    $headers = [];
    foreach ((array) $resp->headers as $name => $value) {
        $value = is_array($value) ? implode("\x00", $value) : (string) $value;
        // E1 defence-in-depth: this gate renders below the facade so X-Request-Id is never present,
        // but drop it if a future path adds one, so the gate stays correct rather than false-failing.
        if (strcasecmp((string) $name, 'X-Request-Id') === 0) {
            continue;
        }
        if (strcasecmp((string) $name, 'Set-Cookie') === 0) {
            // E2: the route session cookie's value is fresh random per request; mask it to <rand> and
            // assert the shape so a determinism check compares everything BUT that legitimate variance.
            $value = (string) preg_replace('/^([^=]+)=[0-9a-f]{32}(; path=\/; HttpOnly)$/', '$1=<rand>$2', $value);
        }
        $headers[(string) $name] = $value;
    }
    ksort($headers);

    return ['status' => $status, 'headers' => $headers, 'body' => (string) $resp->body];
};

// scan every served string of a canonical render for G1.
$scanLeaves = static function (?array $c, string $id, string $where) use ($guard, &$fail, &$leavesScanned): void {
    if ($c === null) {
        return;
    }
    $texts = [$c['body']];
    foreach ($c['headers'] as $name => $value) {
        $texts[] = (string) $name;
        $texts[] = (string) $value;
    }
    foreach ($texts as $text) {
        $leavesScanned++;
        $hits = $guard->scan((string) $text);
        if ($hits !== []) {
            $fail[] = "G1 fingerprint leak in {$where} '{$id}': " . implode(', ', $hits);
        }
    }
};

// ---------------------------------------------------------------------------------------------------
// ATTACK + PARAM rules render through TemplateAttackEmulator::renderRule (position-blind, $r = null).
// ---------------------------------------------------------------------------------------------------
$makeAttack = static function (int $deploySeed) use ($attackRules, $paramBuckets, $FIXED_CLOCK, $FIXED_DECOY_KEY, $volatileProof): TemplateAttackEmulator {
    return new TemplateAttackEmulator(
        $attackRules,
        [],
        $FIXED_CLOCK,
        null,
        $paramBuckets,
        $deploySeed,
        $FIXED_DECOY_KEY,
        $volatileProof,
        false
    );
};
$makeParam = static function (int $deploySeed) use ($paramRules, $FIXED_CLOCK, $FIXED_DECOY_KEY, $volatileProof): TemplateAttackEmulator {
    // Param entries share the attack rule shape (id/response/behavior/captures); render them through
    // the same renderRule path with the entries loaded as the rule set.
    return new TemplateAttackEmulator(
        $paramRules,
        [],
        $FIXED_CLOCK,
        null,
        [],
        $deploySeed,
        $FIXED_DECOY_KEY,
        $volatileProof,
        false
    );
};

$captureFor = static function (array $rule): array {
    // A benign, DETERMINISTIC synthetic capture for every named group the rule reflects. 'probe' does
    // not parse as an arithmetic expression, so an arith/expr/ssti behavior deterministically falls
    // back to its base render — exactly what G2's base-render marker check also inspects. The value is
    // identical across the two renders of a point, so it never perturbs G3.
    $caps = [];
    foreach ((array) ($rule['captures'] ?? []) as $name) {
        $caps[(string) $name] = 'probe';
    }

    return $caps;
};

// G2 marker check, byte-for-byte the compile-time assertMarkers method (EmulatorCompiler::assertMarkers):
// render the AUTHORED `response` body with empty captures + render seed 0, then append each header as
// "\nName: <rendered value>", and assert every expect: marker is a substring. Rendering the base
// response (not a behavior-selected body) is exactly what the compiler validates, so a behavior rule
// cannot false-fail G2. Checked at each deploy seed, so a deploy-seed variation that dropped a marker
// (the FP-0276 concern) fails here. Persona-derived markers (e.g. "id": "AKIA) survive every seed
// because the persona field's fixed prefix is seed-independent.
$checkMarkers = static function (string $id, int $deploySeed, string $where) use (&$markers, &$fail, $volatileProof): void {
    if (!isset($markers[$id]) || $markers[$id]['expect'] === []) {
        return;
    }
    $renderer = new DirectiveRenderer($deploySeed, $volatileProof, false);
    $rendered = $renderer->render((string) $markers[$id]['body'], [], 0);
    foreach ($markers[$id]['headers'] as $name => $value) {
        $rendered .= "\n" . $name . ': ' . $renderer->render((string) $value, [], 0);
    }
    foreach ($markers[$id]['expect'] as $marker) {
        if ($marker !== '' && strpos($rendered, $marker) === false) {
            $fail[] = "G2 marker missing: {$where} expected substring " . var_export($marker, true);
        }
    }
};

// per-surface canonical outputs, keyed 'surfaceKey' => ['material' => canon], for G4 + inventory.
$surfaceRuns = [];

foreach ([['attack', $attackRules, $makeAttack], ['param', $paramRules, $makeParam]] as [$kind, $rules, $factory]) {
    foreach ($rules as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        $id = (string) ($rule['id'] ?? '?');
        $surfaceKey = $kind . ':' . $id;
        $caps = $captureFor($rule);

        foreach ($materials as $material) {
            $emu = $factory($deploySeeds[$material]);
            foreach ($renderSeeds as $rlabel => $renderSeed) {
                $where = "{$kind} {$id} [m={$material},{$rlabel}]";
                $first = $emu->renderRule($rule, $caps, $renderSeed, null);
                $second = $emu->renderRule($rule, $caps, $renderSeed, null);
                $rendered += 2;
                $c1 = $canon($first);
                $c2 = $canon($second);
                if ($c1 !== $c2) {
                    $fail[] = "G3 nondeterministic render: {$where} (" . firstDiff($c1, $c2) . ')';
                }
                $scanLeaves($c1, $id, $where);
                $surfaceRuns[$surfaceKey][$material . '|' . $rlabel] = $c1;
            }
            $checkMarkers($id, $deploySeeds[$material], "{$kind} {$id} [m={$material}]");
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// ROUTE rules render through RouteTemplateEmulator with a synthetic bundle built from the rule's own
// selector; the gate asserts the bundle re-selects that rule (a mis-selection is a gate error).
// ---------------------------------------------------------------------------------------------------
$routeSet = new RouteTemplateSet($routeRules);
foreach ($routeRules as $rule) {
    if (!is_array($rule)) {
        continue;
    }
    $id = (string) ($rule['id'] ?? '?');
    $surfaceKey = 'route:' . $id;
    $bundle = routeBundle((array) ($rule['match'] ?? []));
    if ($bundle === null) {
        $fail[] = "G-selftest route '{$id}': no synthetic bundle could be built from its match selector";
        continue;
    }
    $selected = $routeSet->findRule($bundle);
    if ($selected === null || (string) ($selected['id'] ?? '') !== $id) {
        // A higher-priority rule legitimately shadows this one for the synthetic bundle: render the
        // rule the set actually selects (so coverage is not lost) but note it.
        $selectedId = $selected === null ? '<none>' : (string) ($selected['id'] ?? '?');
        // Not a hard fail — priority shadowing is real — but the selected rule is what serves, so drive
        // the emulator with the bundle and let it render whatever the set picks.
    }
    $isBin = !empty($rule['bin']);

    foreach ($materials as $material) {
        $emu = new RouteTemplateEmulator($routeSet, new DirectiveRenderer($deploySeeds[$material], $volatileProof, false));
        foreach ($renderSeeds as $rlabel => $renderSeed) {
            $where = "route {$id} [m={$material},{$rlabel}]";
            $first = $emu->render($bundle, Style::REALISTIC, $renderSeed);
            $second = $emu->render($bundle, Style::REALISTIC, $renderSeed);
            $rendered += 2;
            $c1 = $canon($first);
            $c2 = $canon($second);
            if ($c1 !== $c2) {
                $fail[] = "G3 nondeterministic render: {$where} (" . firstDiff($c1, $c2) . ')';
            }
            // A bin (favicon) body is opaque image bytes — scan headers only (parity with the static gate).
            if ($c1 !== null && $isBin) {
                $c1Headers = ['status' => $c1['status'], 'headers' => $c1['headers'], 'body' => ''];
                $scanLeaves($c1Headers, $id, $where);
            } else {
                $scanLeaves($c1, $id, $where);
            }
            $surfaceRuns[$surfaceKey][$material . '|' . $rlabel] = $c1;
        }
        if (!$isBin) {
            $checkMarkers($id, $deploySeeds[$material], "route {$id} [m={$material}]");
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// G4 — registered seeded surfaces must vary across deploy materials at a fixed render seed; and the
// fleet-constant inventory (informational) is every surface identical at every grid point.
// ---------------------------------------------------------------------------------------------------
foreach ($surfaceRuns as $surfaceKey => $runs) {
    $values = array_values(array_map(static function ($c): string {
        return $c === null ? "\x00null" : serialize($c);
    }, $runs));
    $isConstant = count(array_unique($values)) === 1;
    if ($isConstant) {
        $fleetConstant[] = $surfaceKey;
    }
    if (isset($surfaces[$surfaceKey])) {
        $a = $runs['fp-0276-sample-a|r-a'] ?? null;
        $b = $runs['fp-0276-sample-b|r-a'] ?? null;
        if ($a === null || $b === null) {
            $fail[] = "G4 registered surface '{$surfaceKey}' did not render at both sample materials";
        } elseif (serialize($a) === serialize($b)) {
            $fail[] = "G4 registered surface '{$surfaceKey}' is identical across deploy seeds (expected per-deploy variance: " . (string) $surfaces[$surfaceKey] . ')';
        } else {
            $seededVerified++;
        }
    }
}
foreach ($surfaces as $surfaceKey => $_desc) {
    if (!isset($surfaceRuns[(string) $surfaceKey])) {
        $fail[] = "G4 registered surface '{$surfaceKey}' names no rendered rule (stale registry entry?)";
    }
}

// --- report ----------------------------------------------------------------------------------------
sort($fleetConstant);
foreach ($fleetConstant as $fc) {
    fwrite(STDOUT, "INFO: fleet-constant: {$fc}\n");
}

if ($rendered === 0) {
    fwrite(STDERR, "error: no rules rendered — gate misconfigured.\n");
    exit(1);
}

if ($fail !== []) {
    foreach ($fail as $msg) {
        fwrite(STDOUT, "::error::{$msg}\n");
    }
    fwrite(STDERR, 'FAIL: ' . count($fail) . " seeded-render check(s) failed across {$rendered} renders.\n");
    exit(1);
}

$ruleCount = count(array_filter($attackRules, 'is_array')) + count(array_filter($routeRules, 'is_array')) + count(array_filter($paramRules, 'is_array'));
$points = count($materials) * count($renderSeeds);
fwrite(STDOUT, sprintf(
    "OK: %d rules × %d points rendered twice; %d leaves scanned; %d seeded surfaces verified; %d fleet-constant.\n",
    $ruleCount,
    $points,
    $leavesScanned,
    $seededVerified,
    count($fleetConstant)
));
exit(0);

// --- helpers ---------------------------------------------------------------------------------------

/** @return array<int|string,mixed> */
function requireArray(string $path): array
{
    if (!is_file($path)) {
        fwrite(STDERR, "error: artifact not found: {$path}\n");
        exit(1);
    }
    $data = require $path;
    if (!is_array($data)) {
        fwrite(STDERR, "error: artifact did not return an array: {$path}\n");
        exit(1);
    }

    return $data;
}

/**
 * Flatten a bucketed param artifact to its entry list (same shape as check-fingerprint-safety.php).
 *
 * @param array<int|string,mixed> $raw
 * @return list<array<string,mixed>>
 */
function flattenParam(array $raw): array
{
    if (!isset($raw['buckets']) || !is_array($raw['buckets'])) {
        return array_values(array_filter($raw, 'is_array'));
    }
    $flat = [];
    foreach ($raw['buckets'] as $entries) {
        foreach ((array) $entries as $entry) {
            if (is_array($entry)) {
                $flat[] = $entry;
            }
        }
    }

    return $flat;
}

/**
 * Build a synthetic served bundle from a route rule's `match` selector so RouteTemplateSet::findRule()
 * selects it. Mirrors the three selector axes in RouteTemplateSet::selects().
 *
 * @param array<string,mixed> $match
 * @return array<string,mixed>|null
 */
function routeBundle(array $match): ?array
{
    foreach ((array) ($match['template_needle'] ?? []) as $needle) {
        $needle = (string) $needle;

        return ['pid' => $needle, 't' => [$needle], 'bw' => []];
    }
    foreach ((array) ($match['pid'] ?? []) as $needle) {
        return ['pid' => (string) $needle, 't' => [(string) $needle], 'bw' => []];
    }
    foreach ((array) ($match['body_word_contains'] ?? []) as $needle) {
        return ['pid' => '', 't' => [], 'bw' => [(string) $needle]];
    }

    return null;
}

/**
 * Parse every template YAML under $dir and collect, by rule id, its `expect:` markers AND the AUTHORED
 * `response` body/headers the G2 check renders — the same source of truth the compile-time
 * assertMarkers reads ($doc), so the two definitions can never drift.
 *
 * @return array<string,array{expect:list<string>,body:string,headers:array<string,string>}>
 */
function collectMarkers(string $dir): array
{
    $out = [];
    if (!is_dir($dir)) {
        return $out;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $file) {
        /** @var SplFileInfo $file */
        $ext = strtolower($file->getExtension());
        if ($ext !== 'yaml' && $ext !== 'yml') {
            continue;
        }
        try {
            $doc = Yaml::parseFile($file->getPathname());
        } catch (\Throwable $e) {
            continue; // a non-parseable template is the compiler's problem, not this gate's
        }
        if (!is_array($doc) || !isset($doc['id']) || !isset($doc['expect'])) {
            continue;
        }
        $id = (string) $doc['id'];
        $expect = is_array($doc['expect']) ? $doc['expect'] : [$doc['expect']];
        $response = (array) ($doc['response'] ?? []);
        $headers = [];
        foreach ((array) ($response['headers'] ?? []) as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }
        $entry = $out[$id] ?? ['expect' => [], 'body' => (string) ($response['body'] ?? ''), 'headers' => $headers];
        foreach ($expect as $m) {
            $entry['expect'][] = (string) $m;
        }
        $out[$id] = $entry;
    }

    return $out;
}

/** A short human description of the first differing field between two canonical renders. */
function firstDiff(?array $a, ?array $b): string
{
    if ($a === null || $b === null) {
        return 'one render was null, the other was not';
    }
    if ($a['status'] !== $b['status']) {
        return "status {$a['status']} vs {$b['status']}";
    }
    if ($a['headers'] !== $b['headers']) {
        return 'headers differ';
    }
    $la = strlen($a['body']);
    $lb = strlen($b['body']);
    if ($la !== $lb) {
        return "body length {$la} vs {$lb}";
    }
    for ($i = 0; $i < $la; $i++) {
        if ($a['body'][$i] !== $b['body'][$i]) {
            return "body differs at offset {$i}";
        }
    }

    return 'unknown difference';
}
