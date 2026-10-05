<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * FP-0357 — false-positive & detection testing report.
 *
 * Runs a curated clean-room benign corpus (tests/fixtures/benign-corpus.php) and a small attack set
 * through the REAL engine's classify() over the full compiled store, and reports:
 *   - the false-positive rate: benign requests that classify into a DECEPTION-SERVING class, and WHICH
 *     rule fired on each (a benign visitor served a decoy is both wrong and a fingerprint);
 *   - the detection rate on blatant attack payloads (a regression guard that a normalizer change can't
 *     silently drop detection).
 *
 * FP = classification ∈ {SCANNER_PROBE, ATTACK_CLASS}. CLEAN and AMBIENT are NOT false positives — AMBIENT
 * is the engine's own anti-FP mechanism (a bare corpus match, e.g. /robots.txt, serves no deception;
 * Verdict.php:16-32). SUSPICIOUS is reserved and unreachable in v1.
 *
 * The guardrail is SET-based: the observed FP set (rule-id → benign labels) must be a SUBSET of the
 * recorded BASELINE_FP (the FP-0582 WON'T-FIX accepted FPs). A NEW rule eating benign traffic — even if it
 * replaces a fixed one at the same count — fails the test. The report is printed on failure.
 */
final class FalsePositiveReportTest extends TestCase
{
    /**
     * Recorded baseline: rule-id => sorted benign sample labels it is accepted to fire on (FP-0582
     * WON'T-FIX). The observed FP set must be a subset of this. (Filled from the first measured run.)
     *
     * @var array<string, string[]>
     */
    private const BASELINE_FP = [
        'attack-sqli' => ['fp0582:information_schema'],
        'attack-fpd-array-pollution' => ['fp0582:fpd-array'],
        'attack-verbose-error-volatile' => ['fp0582:verbose-error-hex'],
        'attack-crs-rce' => ['fp0582:crs-rce-ipconfig'],
        // NEWLY SURFACED by this report (review Finding 1): the GENERATED OWASP-CRS SQLi rule matches a
        // bare "select <words>" in benign content (a product search "select 2024 laptop models") →
        // classifies ATTACK_CLASS. Same class as FP-0582's crs-rce: a GENERATED CRS rule, fixable only at
        // compile-time. Tracked in FP-0583. Baselined here so the guardrail still catches a DIFFERENT new FP.
        'attack-crs-sqli' => ['fpcrs:json-select'],
        // NOTE: FP-0582's fifth accepted FP, attack-open-redirect, is a param-route/reflector rule — it
        // does NOT fire via the store-miss attack scan this differential harness exercises (an absolute/
        // protocol-relative redirect param on a neutral path classifies CLEAN), so it is not captured
        // here. Its FP surfaces only on corpus-key/declared param surfaces, out of this v1's scope.
    ];

    private const DETECTION_FLOOR = 1.0; // blatant payloads must all be detected

    private function engine(): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            true
        );

        return new Honeypot($store, $config);
    }

    private function ruleOf(Verdict $v): string
    {
        if ($v->fakeHandle !== null) {
            $id = $v->fakeHandle->ruleId ?? $v->fakeHandle->key;
            if ($id !== null && $id !== '') {
                return (string) $id;
            }
        }
        $ids = $v->detection->templateIds();

        return $ids !== [] ? (string) $ids[0] : '(unknown)';
    }

    private static function isFalsePositive(Verdict $v): bool
    {
        return $v->classification === Verdict::SCANNER_PROBE || $v->classification === Verdict::ATTACK_CLASS;
    }

    public function test_benign_corpus_false_positive_set_within_baseline(): void
    {
        $engine = $this->engine();
        /** @var array<int,array{label:string,method:string,path:string,query:string,headers:array<string,string>,body:?string}> $corpus */
        $corpus = require __DIR__ . '/fixtures/benign-corpus.php';
        self::assertGreaterThanOrEqual(40, count($corpus), 'benign corpus must be a meaningful size');

        $observed = [];  // rule-id => [labels]
        foreach ($corpus as $s) {
            // Realism FP = the PARAMS/BODY cause a deception-serve. Subtract the path's own by-design
            // behaviour (every honeypot path is a decoy): a request is a param-driven FP only if the full
            // request serves a deception WHILE the bare path (no query/body) does not. This isolates a
            // benign param value tripping an attack rule from the path simply being a corpus-key decoy.
            $full = $engine->classify(new RequestContext($s['method'], $s['path'], $s['query'], $s['headers'], $s['body'], 'shop.example.test'), SiteProfile::empty());
            if (!self::isFalsePositive($full)) {
                continue;
            }
            $pathOnly = $engine->classify(new RequestContext($s['method'], $s['path'], '', $s['headers'], null, 'shop.example.test'), SiteProfile::empty());
            if (self::isFalsePositive($pathOnly)) {
                continue; // path-driven (the path itself is a decoy), not a param-driven realism FP
            }
            $observed[$this->ruleOf($full)][] = $s['label'];
        }
        foreach ($observed as $rule => $labels) {
            sort($labels);
            $observed[$rule] = array_values(array_unique($labels));
        }

        $report = $this->report($observed, count($corpus));

        // SET-SUBSET guardrail: every observed FP (rule + sample) must be an accepted baseline FP.
        $unexpected = [];
        foreach ($observed as $rule => $labels) {
            $baseline = self::BASELINE_FP[$rule] ?? [];
            $new = array_diff($labels, $baseline);
            if ($new !== []) {
                $unexpected[$rule] = array_values($new);
            }
        }
        self::assertSame([], $unexpected, "NEW false positive(s) — a rule started eating benign traffic:\n"
            . json_encode($unexpected, JSON_PRETTY_PRINT) . "\n\nFull report:\n" . $report);

        // No baseline FP should silently DISAPPEAR without updating the baseline (keeps the record honest):
        $missing = [];
        foreach (self::BASELINE_FP as $rule => $labels) {
            $got = $observed[$rule] ?? [];
            $gone = array_diff($labels, $got);
            if ($gone !== []) {
                $missing[$rule] = array_values($gone);
            }
        }
        self::assertSame([], $missing, "A recorded baseline FP no longer fires (good! — update BASELINE_FP):\n"
            . json_encode($missing, JSON_PRETTY_PRINT) . "\n\nFull report:\n" . $report);
    }

    public function test_detection_rate_on_blatant_attacks_at_floor(): void
    {
        $engine = $this->engine();
        // Review Finding 2: neutral store-miss paths (bare path CLEAN) so the PAYLOAD is the sole cause —
        // else a payload-detection regression would be masked by the path itself being a decoy.
        $attacks = [
            'sqli-tautology' => ['/shop/atk-1', "id=1' OR '1'='1"],
            'sqli-union' => ['/shop/atk-2', 'id=1 union select password from users'],
            'xss-script' => ['/shop/atk-3', 'q=' . rawurlencode('<script>alert(1)</script>')],
            'cmdi-semicolon' => ['/shop/atk-4', 'host=' . rawurlencode('127.0.0.1;id')],
            'lfi-passwd' => ['/shop/atk-5', 'file=' . rawurlencode('../../../../etc/passwd')],
            'ssti-numeric' => ['/shop/atk-6', 'q=' . rawurlencode('{{1337*7}}')],
        ];
        $detected = 0;
        $missed = [];
        foreach ($attacks as $label => [$path, $query]) {
            // Guard: the bare path must be CLEAN so the payload is what gets detected, not the path.
            $bare = $engine->classify(new RequestContext('GET', $path, '', [], null, 'shop.example.test'), SiteProfile::empty());
            self::assertFalse(self::isFalsePositive($bare), "attack path {$label} must be a neutral store-miss path (bare CLEAN)");
            $v = $engine->classify(new RequestContext('GET', $path, $query, [], null, 'shop.example.test'), SiteProfile::empty());
            if (self::isFalsePositive($v)) {
                $detected++;
            } else {
                $missed[$label] = $v->classification;
            }
        }
        $rate = $detected / count($attacks);
        self::assertGreaterThanOrEqual(self::DETECTION_FLOOR, $rate,
            "detection below floor; missed: " . json_encode($missed, JSON_PRETTY_PRINT));
    }

    /** @param array<string,string[]> $observed */
    private function report(array $observed, int $total): string
    {
        $fpCount = 0;
        foreach ($observed as $labels) {
            $fpCount += count($labels);
        }
        $summary = [
            'total_benign' => $total,
            'fp_count' => $fpCount,
            'fp_rate' => $total > 0 ? round($fpCount / $total, 4) : 0.0,
            'per_rule' => $observed,
        ];

        return json_encode($summary, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}
