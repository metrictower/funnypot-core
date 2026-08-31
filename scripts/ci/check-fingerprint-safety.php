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
 * With no --index, the compiled attack, route, AND param served-response artifacts under
 * resources/compiled/ are scanned (each is a surface where emulator content lands). Attack rules
 * carry the served body/headers under `response`; route rules carry them at top level; the param
 * artifact is bucketed and flattened to its entries first — all shapes are handled. The denylist is
 * resources/fingerprint-denylist.php (tracked, append-only).
 */

use Funnypot\Core\Compiler\Crs\FingerprintGuard;

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
    ], 'is_file'));
}

$guard = FingerprintGuard::fromPackage();
$leaks = 0;
$scanned = 0;

// Every scan-worthy served string in one rule-shaped array: the body, each header name/value, the
// Set-Cookie NAME emitted verbatim (RouteTemplateEmulator::render), and the taunt comment-syntax
// strings written into the body (RouteTemplateEmulator::applyTaunt).
$collect = static function (array $src): array {
    $texts = [(string) ($src['body'] ?? '')];
    foreach ((array) ($src['headers'] ?? []) as $name => $value) {
        $texts[] = (string) $name;
        $texts[] = (string) $value;
    }
    $texts[] = (string) ($src['set_cookie'] ?? '');
    if (isset($src['taunt']) && is_array($src['taunt'])) {
        foreach (['open', 'close', 'key'] as $part) {
            $texts[] = (string) ($src['taunt'][$part] ?? '');
        }
    }

    return $texts;
};

foreach ($indexes as $index) {
    if (!is_file($index)) {
        if ($explicit) {
            fwrite(STDERR, "error: --index not found: {$index}\n");
            exit(1);
        }
        fwrite(STDERR, "warning: index not found, skipping: {$index}\n");
        continue;
    }
    $rules = require $index;
    if (!is_array($rules)) {
        if ($explicit) {
            fwrite(STDERR, "error: --index did not return an array: {$index}\n");
            exit(1);
        }
        continue;
    }
    // The param artifact is bucketed (`['schema'=>1,'buckets'=>['<seg>'=>[entry,...]]]`); flatten
    // to the flat entry list the rule loop expects. Attack/route artifacts are already flat and
    // have no `buckets` key, so they pass through unchanged. Param entries carry `response`, so the
    // same $collect + branch-descent below covers them.
    if (isset($rules['buckets']) && is_array($rules['buckets'])) {
        $flat = [];
        foreach ($rules['buckets'] as $entries) {
            foreach ((array) $entries as $entry) {
                $flat[] = $entry;
            }
        }
        $rules = $flat;
    }
    foreach ($rules as $rule) {
        if (!is_array($rule)) {
            continue;
        }
        // Binary rule (FP-0230): a `bin` route rule's `body` is base64 (opaque ASCII image bytes),
        // not a textual matcher surface, so it has nothing for the denylist to legitimately hit —
        // skip it to avoid scanning opaque bytes and any false-positive substring inside base64.
        if (!empty($rule['bin'])) {
            continue;
        }
        $scanned++;
        $id = (string) ($rule['id'] ?? '?');
        // Two compiled shapes: attack rules nest served content under `response`; route rules carry
        // it at top level. Scan BOTH so a rule that ever carried both is fully covered.
        $texts = array_merge($collect((array) ($rule['response'] ?? [])), $collect($rule));
        // A `branch` rule ALSO serves each case's response and the default's response (body+headers
        // shaped) when a case fires — those never appear in the top-level body, so collect them too.
        if (isset($rule['branch']) && is_array($rule['branch'])) {
            foreach ((array) ($rule['branch']['cases'] ?? []) as $case) {
                if (is_array($case) && isset($case['response']) && is_array($case['response'])) {
                    $texts = array_merge($texts, $collect($case['response']));
                }
            }
            if (isset($rule['branch']['default']['response']) && is_array($rule['branch']['default']['response'])) {
                $texts = array_merge($texts, $collect($rule['branch']['default']['response']));
            }
        }
        // A `traversal-read` rule serves each allow entry's `content` (and the default's) — a
        // synthesized file body under a nested key that never reaches the top-level body, so descend
        // into every one, same class of coverage as branch.
        if (isset($rule['traversal-read']) && is_array($rule['traversal-read'])) {
            foreach ((array) ($rule['traversal-read']['allow'] ?? []) as $entry) {
                if (is_array($entry) && isset($entry['content']) && is_array($entry['content'])) {
                    $texts = array_merge($texts, $collect($entry['content']));
                }
            }
            if (isset($rule['traversal-read']['default']['content']) && is_array($rule['traversal-read']['default']['content'])) {
                $texts = array_merge($texts, $collect($rule['traversal-read']['default']['content']));
            }
        }
        // An `arith-eval` rule serves its `response` when it computes a hit — a nested node that never
        // reaches the top-level body, so descend into it.
        if (isset($rule['arith-eval']['response']) && is_array($rule['arith-eval']['response'])) {
            $texts = array_merge($texts, $collect($rule['arith-eval']['response']));
        }
        // An `iterate` rule serves the wrap open/close body, the per-sub-call `item`, the
        // `response` headers on the multicall success path, and the `empty`/`fallback` responses —
        // all nested served shapes the top-level body never carries.
        if (isset($rule['iterate']) && is_array($rule['iterate'])) {
            $it = $rule['iterate'];
            $texts[] = (string) ($it['wrap']['open'] ?? '');
            $texts[] = (string) ($it['wrap']['close'] ?? '');
            if (isset($it['item']) && is_array($it['item'])) {
                $texts = array_merge($texts, $collect($it['item']));
            }
            if (isset($it['response']) && is_array($it['response'])) {
                $texts = array_merge($texts, $collect($it['response']));
            }
            foreach (['empty', 'fallback'] as $k) {
                if (isset($it[$k]['response']) && is_array($it[$k]['response'])) {
                    $texts = array_merge($texts, $collect($it[$k]['response']));
                }
            }
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

if ($scanned === 0) {
    fwrite(STDERR, "error: no compiled responses scanned — gate misconfigured.\n");
    exit(1);
}

if ($leaks > 0) {
    fwrite(STDERR, "FAIL: {$leaks} fingerprint leak(s) across {$scanned} compiled response(s).\n");
    exit(1);
}

fwrite(STDOUT, "OK: {$scanned} compiled response(s) carry no upstream-detector signature.\n");
exit(0);
