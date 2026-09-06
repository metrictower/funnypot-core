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
 *                            behavior rule that picks a non-base body cannot false-fail this). This is
 *                            AUTHORED-marker validation, independent of selector reachability: a route
 *                            rule shadowed by a higher-priority sibling is still marker-checked here,
 *                            but that is not proof runtime served it (G3/G4 over the SELECTED bytes is).
 *   G3  determinism       — the two renders at one (deploySeed, renderSeed) point are byte-identical,
 *                            modulo the ONE legitimate per-request variance these render paths carry:
 *                            the route Set-Cookie random value (E2). This gate renders BELOW the
 *                            respond() facade, so the X-Request-Id (E1) is never emitted here;
 *                            volatileProof (E3) is off, latency (E4) is metadata not bytes, and the
 *                            Clock (E5) is fixed — none can appear in this output by construction.
 *   G4  cross-deploy       — every surface in resources/seeded-surfaces.php differs between two deploy
 *       variance             materials at a fixed render seed (a regression that re-constants a
 *                            converted surface is caught here).
 *   G7  legacy-prefix law — no rendered byte carries the retired `fp-` class prefix (the funnypot-
 *       (FP-0283)            signature tell FP-0283 closed by seeding the class-prefix word). Scoped to
 *                            class attributes / CSS selectors / the `fp-XXXX-` class shape so a path byte
 *                            like `/flatpress/fp-content/` never false-positives. Runs in $scanLeaves, so
 *                            it covers every leg (attack/param, authed, route, synth); at baseline it
 *                            fails on the 102/103 + authed phpMyAdmin renders (non-vacuous).
 *
 * MINIMAL-SYNTH leg (FP-0281, the --nuclei index). ResponseSynthesizer's minimal-synth output is not a
 * rendered RULE, so the loops above never see it; this leg renders every bundle of the compiled nuclei
 * index through ResponseSynthesizer at MINIMAL, twice per grid point, so the deploy-seeded scaffold
 * (bw word ORDER) and witness-header NAMES get the same G1 (fingerprint-clean) + G3 (render-twice
 * determinism) treatment, plus:
 *   G5  served-set        — the set of served (route,i) keys is IDENTICAL at every grid point (a
 *       invariance          seed-dependent skip would be a matcher-servability regression).
 *   G6  body-order floor  — among multi-word (≥2 bw) bundles, ≥50% differ between the two sample deploy
 *                            materials (else the permutation silently re-constanted). ARMED only when
 *                            resources/seeded-surfaces.php registers `synth:minimal-body-order`, so an
 *                            operator-commit sequencing (FP-0280) that lands the registry entry later
 *                            can hang its own floor on the same switch.
 * Two AGGREGATE `synth:` surfaces are recorded so the G4 loop + fleet-constant inventory treat the leg
 * like any rule surface. This leg is also FP-0280's M1 infra (it collects the served rx vector in the
 * same loop). This script reads compiled artifacts + template YAML only; it writes and compiles NOTHING
 * (zero compiled-byte impact). It also PRINTS (never fails on) the fleet-constant inventory.
 *
 * AUTHED DECOY leg (FP-0282, the `authed:` kind). The attack loop renders every rule position-blind
 * ($r = null), where a decoy-session gate fails closed to its login page — so its seeded table story
 * (DecoyTables: tree/whitelist names, column convention, dropped table) is never rendered above. This
 * leg mints a fixed-key s=1 cookie and renders each gate rule WITH a request, so G1/G3/G4 see the authed
 * body, plus:
 *   G-authed  servability   — the authed body must render (not the fail-closed login/base decline); a
 *                             seeded table name tripping the runtime FingerprintGuard at some seed is
 *                             caught here rather than leaking as a silent decline.
 *
 * ROUTE PRIORITY SHADOWS. First-match route selection means a synthetic witness built from one rule's
 * selector can be captured by a higher-priority sibling. The route leg keeps the requested and selected
 * ids distinct: a normal selection is inventoried as `route:<requested>`, a shadow as the directional
 * alias `route-shadow:<requested>-><selected>` with one deterministic `INFO: route shadow: …` line, and
 * a null/id-less selection is a hard self-test failure. G3/G4 always scan the actual SELECTED bytes and
 * classify binary-vs-text by the SELECTED rule, so a shadow never certifies the unreachable requested
 * renderer under its own key.
 *
 *   php scripts/ci/check-seeded-render.php
 *     [--attack=PATH] [--routes=PATH] [--param=PATH] [--templates=DIR] [--surfaces=PATH] [--nuclei=PATH]
 *     [--volatile-proof]   (test-only: arm volatileProof so a {{volatile.*}} body FAILS G3)
 *
 * Exit code 1 on any G1–G6 failure or on zero rules rendered (fail-closed floor).
 */

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Contracts\Clock;
use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\EmulatedContent;
use Funnypot\Core\Response\RouteTemplateEmulator;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\Synthesis\SynthScaffold;
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
    'nuclei' => $root . '/resources/compiled/nuclei-index.full.php',
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
        // G7 legacy-prefix law (FP-0283): no rendered byte may carry the retired `fp-` class prefix —
        // the funnypot-signature tell FP-0283 closed by seeding the class-prefix word. Scoped to class
        // attributes (`class="…fp-`), CSS selectors (`.fp-<letter>`) and the `fp-XXXX-` class shape so
        // path bytes like `/flatpress/fp-content/` never false-positive.
        if (preg_match('~class="[^"]*\bfp-|\.fp-[a-z]|\bfp-[0-9a-f]{4}-~', (string) $text) === 1) {
            $fail[] = "G7 legacy fp- class prefix in {$where} '{$id}'";
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
// AUTHED DECOY leg (FP-0282). The attack loop above renders every rule position-blind ($r = null), so a
// decoy-session GATE rule fails CLOSED to its login page and its seeded table story is never rendered —
// registering `attack:<gate>` alone would pass G4 for the wrong reason (the login page already varies
// through {{persona.*}}). This leg mints a fixed-key s=1 cookie and renders each gate rule WITH a
// request, so G1/G3/G4 actually see the table tree, the ?table= whitelist names, and the column
// convention this deploy serves. Recorded as `authed:<id>` surfaces so the G4 loop + fleet-constant
// inventory treat them like any rule surface.
//   G-authed  servability — the authed body must render (not the fail-closed login/base decline); a
//              seeded name tripping the runtime FingerprintGuard at some seed is caught here.
// ---------------------------------------------------------------------------------------------------
$authedGateRenders = 0;
foreach ($attackRules as $rule) {
    if (!is_array($rule)) {
        continue;
    }
    $cfg = is_array($rule['decoy-session'] ?? null) ? $rule['decoy-session'] : [];
    if ((string) ($rule['behavior'] ?? '') !== 'decoy-session' || (string) ($cfg['mode'] ?? '') !== 'gate') {
        continue;
    }
    $id = (string) ($rule['id'] ?? '?');
    // Owned-path selection mirrors ManifestBuilder::skinLinks (:433-439): default to $owned[0], only
    // UPGRADE to an …/index.php entry when one exists. Requiring /index.php would silently skip the WP
    // gate (its compiled owns_path is ["/wp-admin"]).
    $owned = array_values(array_filter((array) ($rule['owns_path'] ?? []), 'is_string'));
    if ($owned === []) {
        fwrite(STDOUT, "INFO: authed leg skipped gate '{$id}' (no owns_path)\n");
        continue;
    }
    $ownedPath = $owned[0];
    foreach ($owned as $p) {
        if (substr($p, -10) === '/index.php') {
            $ownedPath = $p;
            break;
        }
    }
    $cookieName = (string) ($cfg['cookie_name'] ?? 'phpMyAdmin');
    $cookiePath = (string) ($cfg['cookie_path'] ?? '/');
    $surfaceKey = 'authed:' . $id;

    foreach ($materials as $material) {
        $deploySeed = $deploySeeds[$material];
        $emu = $makeAttack($deploySeed);
        foreach ($renderSeeds as $rlabel => $renderSeed) {
            $where = "authed {$id} [m={$material},{$rlabel}]";
            // Resolve the cookie name exactly as handleDecoySession does (:1074-1078), then mint an s=1
            // cookie for that name (the ManifestBuilder :442-448 split) and present it on the request.
            $renderedName = (new DirectiveRenderer($deploySeed, $volatileProof, false))->render($cookieName, [], $renderSeed);
            if ($renderedName === '') {
                $renderedName = $cookieName;
            }
            $mint = (new DecoySession($FIXED_DECOY_KEY))->mintCookie($renderedName, $cookiePath);
            $semi = strpos($mint, ';');
            $pair = $semi === false ? $mint : substr($mint, 0, $semi);
            $r = new RequestContext('GET', $ownedPath, '', ['Cookie' => $pair]);
            $first = $emu->renderRule($rule, [], $renderSeed, $r);
            $second = $emu->renderRule($rule, [], $renderSeed, $r);
            $rendered += 2;
            $authedGateRenders += 2;
            $c1 = $canon($first);
            $c2 = $canon($second);
            $base = $canon($emu->renderRule($rule, [], $renderSeed, null));
            if ($c1 !== $c2) {
                $fail[] = "G3 nondeterministic render: {$where} (" . firstDiff($c1, $c2) . ')';
            }
            if ($c1 === null || $c1 === $base) {
                $fail[] = "G-authed: gate '{$id}' served its declined/base body at {$where} (fail-closed or gate miss)";
            }
            $scanLeaves($c1, $id, $where);
            $surfaceRuns[$surfaceKey][$material . '|' . $rlabel] = $c1;
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// ROUTE rules render through RouteTemplateEmulator with a synthetic bundle built from the rule's own
// selector. First-match priority means the set can pick a HIGHER-priority rule than the one the bundle
// was built from (a priority shadow); RouteTemplateEmulator then serves THAT selected rule's bytes. So
// the gate keeps the requested and selected identities distinct: it scans the actual selected bytes and
// inventories a normal selection under `route:<requested>`, a shadow under the directional alias
// `route-shadow:<requested>-><selected>`. A shadow is never filed as coverage for the unreachable
// requested renderer, so registering `route:<shadowed-requested>` fails closed as a stale entry.
// Binary-vs-text scanning follows the SELECTED rule's `bin` (the served bytes are its render). A null or
// id-less selection is a self-test failure (a config/selector regression), rendered and inventoried
// nowhere. G2 (checkMarkers) stays REQUESTED-rule authored-marker validation — valuable even for an
// unreachable rule, but not proof runtime served it — so it gates on the requested rule's own `bin`.
// ---------------------------------------------------------------------------------------------------
$routeSet = new RouteTemplateSet($routeRules);
$routeShadows = []; // list<string> "<requested> -> <selected>" — one deterministic INFO line each
foreach ($routeRules as $rule) {
    if (!is_array($rule)) {
        continue;
    }
    $requestedId = (string) ($rule['id'] ?? '?');
    $bundle = routeBundle((array) ($rule['match'] ?? []));
    if ($bundle === null) {
        $fail[] = "G-selftest route '{$requestedId}': no synthetic bundle could be built from its match selector";
        continue;
    }
    $selected = $routeSet->findRule($bundle);
    if ($selected === null) {
        // Defense-in-depth: routeBundle() and RouteTemplateSet::selects() are symmetric over the same
        // rule set, so a non-null bundle always selects at least its own rule — a null here is a
        // selector regression, not coverage. Render nothing, inventory nothing.
        $fail[] = "G-selftest route '{$requestedId}': synthetic bundle selected no rule";
        continue;
    }
    $selectedId = isset($selected['id']) ? (string) $selected['id'] : '';
    if ($selectedId === '') {
        // An id-less selected rule cannot be attributed truthfully; fail rather than mint a `?` key.
        $fail[] = "G-selftest route '{$requestedId}': selected rule has no usable id";
        continue;
    }
    if ($selectedId === $requestedId) {
        $surfaceKey = 'route:' . $requestedId;
        $diag = "route {$requestedId}";
    } else {
        $surfaceKey = 'route-shadow:' . $requestedId . '->' . $selectedId;
        $diag = "route shadow {$requestedId} -> {$selectedId}";
        $routeShadows[] = "{$requestedId} -> {$selectedId}";
    }
    // Selected-rule bin drives the served-byte scan; the requested rule's bin still gates its own G2
    // authored-marker check, so a requested-text/selected-binary shadow neither skips a real marker
    // check nor feeds opaque bytes to the text scan.
    $selectedIsBin = !empty($selected['bin']);
    $isBin = !empty($rule['bin']);

    foreach ($materials as $material) {
        $emu = new RouteTemplateEmulator($routeSet, new DirectiveRenderer($deploySeeds[$material], $volatileProof, false));
        foreach ($renderSeeds as $rlabel => $renderSeed) {
            $where = "{$diag} [m={$material},{$rlabel}]";
            $first = $emu->render($bundle, Style::REALISTIC, $renderSeed);
            $second = $emu->render($bundle, Style::REALISTIC, $renderSeed);
            $rendered += 2;
            $c1 = $canon($first);
            $c2 = $canon($second);
            if ($c1 !== $c2) {
                $fail[] = "G3 nondeterministic render: {$where} (" . firstDiff($c1, $c2) . ')';
            }
            // A bin (favicon) body is opaque image bytes — scan headers only (parity with the static
            // gate). The SELECTED rule decides this: the served bytes are its render, not the requested
            // rule's, so a shadow that serves a text body is fully leaf-scanned even when the requested
            // rule was binary (and vice versa).
            if ($c1 !== null && $selectedIsBin) {
                $c1Headers = ['status' => $c1['status'], 'headers' => $c1['headers'], 'body' => ''];
                $scanLeaves($c1Headers, $selectedId, $where);
            } else {
                $scanLeaves($c1, $selectedId, $where);
            }
            $surfaceRuns[$surfaceKey][$material . '|' . $rlabel] = $c1;
        }
        if (!$isBin) {
            $checkMarkers($requestedId, $deploySeeds[$material], "authored route {$requestedId} [m={$material}]");
        }
    }
}
// One deterministic shadow line per requested rule (compiled-rule order), outside both nested loops.
foreach ($routeShadows as $shadow) {
    fwrite(STDOUT, "INFO: route shadow: {$shadow}\n");
}

// ---------------------------------------------------------------------------------------------------
// MINIMAL-SYNTH leg (FP-0281): render every nuclei-index bundle through ResponseSynthesizer at MINIMAL,
// twice per grid point, so the deploy-seeded scaffold order + witness-header names get G1/G3, plus the
// served-set law (G5) and the multi-word body-order floor (G6). Two aggregate `synth:` surfaces feed G4.
// ---------------------------------------------------------------------------------------------------
$synthBundleCount = 0;
$synthServedRef = null;      // reference served-set (G5)
$synthServedRefKey = null;
$bodyAtA = [];               // (route#i) => body at fp-0276-sample-a|r-a  (G6)
$bodyAtB = [];               // (route#i) => body at fp-0276-sample-b|r-a  (G6)
$multiWordKeys = [];         // (route#i) => true for served bundles with ≥2 bw words

if (is_file($opt['nuclei'])) {
    ini_set('memory_limit', '512M'); // raise-only; the full index + synthesizer peak ~48 MB
    $nuclei = requireArray($opt['nuclei']);
    $nucleiRoutes = (isset($nuclei['routes']) && is_array($nuclei['routes'])) ? $nuclei['routes'] : [];

    // A synthetic name is one this leg emits: a pool name, or the deterministic overflow shape. Defined
    // positively (not by chrome/typed exclusion) so the aggregate is exact on any index.
    $poolNames = array_flip(SynthScaffold::allNames());
    $isSyntheticName = static function (string $name) use ($poolNames): bool {
        return isset($poolNames[$name]) || preg_match('/^X-[A-Z][a-z]+-[A-Z][a-z]+-\d+$/', $name) === 1;
    };

    $firstMaterial = $materials[0];
    $firstRlabel = (string) array_key_first($renderSeeds);

    foreach ($materials as $material) {
        // deploySeed set ⇒ the render seed is inert on the minimal path (identitySeed returns the
        // deploySeed); a future null-seed regression would surface as cross-material variance instead.
        $synth = new ResponseSynthesizer(null, Style::MINIMAL, null, null, $deploySeeds[$material]);
        foreach ($renderSeeds as $rlabel => $renderSeed) {
            $gridKey = $material . '|' . $rlabel;
            $renderStr = 'gate.example|' . $material;
            $bodyStream = '';
            $nameSet = [];
            $served = [];
            $gridMultiWord = 0;
            foreach ($nucleiRoutes as $route => $entry) {
                foreach ((array) ($entry['b'] ?? []) as $i => $bundle) {
                    if (!is_array($bundle)) {
                        continue;
                    }
                    $key = $route . '#' . $i;
                    $c1 = $canon($synth->synthesize($bundle, Detection::none(), $renderStr));
                    $c2 = $canon($synth->synthesize($bundle, Detection::none(), $renderStr));
                    if ($material === $firstMaterial && $rlabel === $firstRlabel) {
                        $synthBundleCount++;
                    }
                    if ($c1 === null) {
                        continue; // not served (seed-independent: no registry / anchored / eq overflow)
                    }
                    if ($c1 !== $c2) {
                        $fail[] = "G3 nondeterministic render: synth {$key} [m={$material},{$rlabel}] (" . firstDiff($c1, $c2) . ')';
                    }
                    $scanLeaves($c1, $key, "synth {$key} [m={$material},{$rlabel}]");
                    $served[] = $key;
                    $bodyStream .= $key . "\x1f" . $c1['body'] . "\x1e";
                    foreach (array_keys($c1['headers']) as $hn) {
                        if ($isSyntheticName((string) $hn)) {
                            $nameSet[(string) $hn] = true;
                        }
                    }
                    if (count((array) ($bundle['bw'] ?? [])) >= 2) {
                        $gridMultiWord++;
                        $multiWordKeys[$key] = true;
                        if ($gridKey === 'fp-0276-sample-a|r-a') {
                            $bodyAtA[$key] = $c1['body'];
                        } elseif ($gridKey === 'fp-0276-sample-b|r-a') {
                            $bodyAtB[$key] = $c1['body'];
                        }
                    }
                }
            }

            // G5 served-set invariance (only meaningful once ≥1 bundle rendered).
            sort($served);
            if ($synthServedRef === null) {
                $synthServedRef = $served;
                $synthServedRefKey = $gridKey;
            } elseif ($served !== $synthServedRef) {
                $fail[] = "G5 synth served-set differs across seeds: {$gridKey} vs {$synthServedRefKey}";
            }

            // Aggregate surfaces (canon shape) so G4 + the fleet-constant inventory treat them as rules.
            // Recorded ONLY when the leg produced something to measure at this grid point — no multi-word
            // bundle ⇒ minimal-body-order is NOT recorded, so a registered key over an empty/single-word
            // leg fails as a stale-registry entry (M1(b): fail-closed, never a false "identical", never a
            // div-by-zero). Servability is seed-independent, so this records consistently at every point.
            if ($gridMultiWord > 0) {
                $surfaceRuns['synth:minimal-body-order'][$gridKey] = ['status' => 0, 'headers' => [], 'body' => hash('sha256', $bodyStream)];
            }
            if ($nameSet !== []) {
                ksort($nameSet);
                $surfaceRuns['synth:witness-header-names'][$gridKey] = ['status' => 0, 'headers' => [], 'body' => hash('sha256', implode("\n", array_keys($nameSet)))];
            }
        }
    }
}

// G6 — the multi-word body-order floor, ARMED only when the surface is registered (so an operator-commit
// sequencing can land the registry entry later). Skipped (never div-by-zero) when the leg synthesized no
// multi-word bundles at both sample materials.
$synthMultiWord = 0;
$synthMultiWordDiff = 0;
foreach (array_keys($multiWordKeys) as $key) {
    if (isset($bodyAtA[$key], $bodyAtB[$key])) {
        $synthMultiWord++;
        if ($bodyAtA[$key] !== $bodyAtB[$key]) {
            $synthMultiWordDiff++;
        }
    }
}
if ($synthMultiWord > 0) {
    $pct = $synthMultiWordDiff / $synthMultiWord;
    fwrite(STDOUT, sprintf(
        "INFO: synth bundles=%d served-set-size=%d multi-word=%d differing-at-a·b=%d (%.1f%%)\n",
        $synthBundleCount,
        $synthServedRef === null ? 0 : count($synthServedRef),
        $synthMultiWord,
        $synthMultiWordDiff,
        $pct * 100
    ));
    if (isset($surfaces['synth:minimal-body-order']) && $pct < 0.5) {
        $fail[] = sprintf(
            'G6 synth body-order floor: only %d/%d (%.1f%%) multi-word bundles differ across deploy seeds (need ≥50%%)',
            $synthMultiWordDiff,
            $synthMultiWord,
            $pct * 100
        );
    }
} elseif ($synthBundleCount > 0) {
    fwrite(STDOUT, "INFO: synth bundles={$synthBundleCount} served-set-size=" . ($synthServedRef === null ? 0 : count($synthServedRef)) . " multi-word=0 (body-order floor skipped)\n");
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
    "OK: %d rules × %d points rendered twice; %d bundles synthesized; %d authed gate renders; %d leaves scanned; %d seeded surfaces verified; %d fleet-constant.\n",
    $ruleCount,
    $points,
    $synthBundleCount,
    $authedGateRenders,
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
