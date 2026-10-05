<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Waf\Lexer\SqlToken;
use Funnypot\Core\Waf\SqlTokenStreamValidator;
use PHPUnit\Framework\TestCase;

/**
 * FP-0436 Phase 1 — the G1 RISK GATE, measured in isolation on the validator's own accept/reject over
 * clean-room labeled corpora (NOT end-to-end). This is the go/no-go evidence for wiring the validator
 * into the fingerprint-critical pipeline in Phase 2: if the false-positive bound can't be met, the
 * validator must NOT be wired (the plan's STOP rule). The thresholds here ARE that gate.
 *
 *  - FP: upper 95% Wilson CI of the benign false-positive rate must be < 0.5%.
 *  - TP: recall on the obfuscation-delta attack corpus must be >= 95% (the incremental coverage the
 *        @rx store 404s today; blatant payloads are out of scope — already caught).
 *  - Every named FP-firewall shape rejects; the FalsePositiveReportTest-baselined `fpcrs:json-select`
 *    benign ("select 2024 laptop models") must NOT newly flag (zero-new-FP constraint).
 */
final class Fp0436G1GateTest extends TestCase
{
    private const FP_CI_MAX = 0.005;     // 0.5%
    private const TP_RECALL_MIN = 0.95;  // 95%

    /** @return array<int,array{label:string,value:string}> */
    private function benign(): array
    {
        return require __DIR__ . '/fixtures/waf-benign-corpus.php';
    }

    /** @return array<int,array{label:string,value:string}> */
    private function delta(): array
    {
        return require __DIR__ . '/fixtures/waf-sqli-delta-corpus.php';
    }

    public function test_benign_false_positive_upper_ci_is_below_half_a_percent(): void
    {
        $corpus = $this->benign();
        $n = count($corpus);
        self::assertGreaterThanOrEqual(1000, $n, 'the benign corpus must be large enough for a meaningful FP bound');

        $validator = new SqlTokenStreamValidator();
        $fp = 0;
        $hits = [];
        foreach ($corpus as $row) {
            $p = $validator->classify($row['value']);
            if ($p !== null) {
                $fp++;
                $hits[] = $row['label'] . ' [' . $p . ']: ' . $row['value'];
            }
        }

        $upper = $this->wilsonUpper($fp, $n);
        self::assertLessThan(
            self::FP_CI_MAX,
            $upper,
            sprintf(
                "G1 FP gate FAILED: %d/%d FPs, Wilson upper-95%% CI %.4f%% >= %.2f%%.\nHits:\n  %s",
                $fp,
                $n,
                $upper * 100,
                self::FP_CI_MAX * 100,
                implode("\n  ", $hits)
            )
        );
    }

    public function test_obfuscation_delta_recall_meets_floor(): void
    {
        $corpus = $this->delta();
        $n = count($corpus);
        $validator = new SqlTokenStreamValidator();
        $hit = 0;
        $miss = [];
        foreach ($corpus as $row) {
            if ($validator->classify($row['value']) !== null) {
                $hit++;
            } else {
                $miss[] = $row['label'] . ': ' . $row['value'];
            }
        }

        $recall = $hit / $n;
        self::assertGreaterThanOrEqual(
            self::TP_RECALL_MIN,
            $recall,
            sprintf("G1 TP floor FAILED: recall %.1f%% < %.0f%%.\nMisses:\n  %s", $recall * 100, self::TP_RECALL_MIN * 100, implode("\n  ", $miss))
        );
    }

    public function test_every_named_firewall_shape_rejects(): void
    {
        $validator = new SqlTokenStreamValidator();
        foreach ($this->benign() as $row) {
            if (strncmp($row['label'], 'named:', 6) !== 0) {
                continue;
            }
            self::assertNull($validator->classify($row['value']), "named FP shape must reject: {$row['label']} => {$row['value']}");
        }
    }

    public function test_baselined_json_select_benign_does_not_newly_flag(): void
    {
        // FalsePositiveReportTest baselines attack-crs-sqli => ['fpcrs:json-select'] on exactly this
        // value; the validator must not ADD a new FP source for it (zero-new-FP constraint, G1).
        self::assertNull((new SqlTokenStreamValidator())->classify('select 2024 laptop models'));
    }

    public function test_token_contract_version_is_pinned(): void
    {
        // FP-0426 / FP-0437 bind to this enum; a renumber or silent bump is a breaking change.
        self::assertSame(1, SqlToken::CONTRACT_VERSION);
    }

    /** Upper bound of the 95% Wilson score interval for $k successes in $n trials. */
    private function wilsonUpper(int $k, int $n): float
    {
        if ($n === 0) {
            return 1.0;
        }
        $z = 1.959963984540054; // 97.5th percentile of the standard normal
        $phat = $k / $n;
        $z2 = $z * $z;
        $den = 1 + $z2 / $n;
        $centre = $phat + $z2 / (2 * $n);
        $margin = $z * sqrt($phat * (1 - $phat) / $n + $z2 / (4 * $n * $n));

        return ($centre + $margin) / $den;
    }
}
