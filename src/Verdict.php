<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * Result of classify() — what a request IS, as content (two-phase design §2.1). Content
 * detection only: no gates, no I/O, no "should we act?". The policy reads it to decide.
 *
 * Serializable so it can cross the policy boundary, be cached, or be logged.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, class-const enum.
 */
final class Verdict
{
    /** classification enum (const strings, not a PHP enum — 7.3 floor). */
    public const CLEAN = 'clean';
    /**
     * A path fetched unprompted by browsers, crawlers and platforms (resources/ambient-paths.php):
     * a bare corpus match here is not itself evidence. An OOB/honeytoken witness is request-level
     * proof the fetch was NOT unprompted, so the fold bumps AMBIENT to SCANNER_PROBE.
     */
    public const AMBIENT = 'ambient';
    public const SCANNER_PROBE = 'scanner-probe';
    public const ATTACK_CLASS = 'attack-class';
    /**
     * Reserved: v1 computes the request-shape signals + anomaly but never classifies a bare
     * anomaly here — the composite bot decision is the policy's (S2/S3). The value exists so
     * the "weak signal alone never deceives" rule stays expressible.
     */
    public const SUSPICIOUS = 'suspicious';

    /** @var string one of the class constants above */
    public $classification;

    /** @var Detection matched template/attack ids + severity + tags */
    public $detection;

    /** @var string highest nuclei severity across the match ('' when none) */
    public $severity;

    /** @var int cheap cumulative anomaly (folds the request-shape signal weights); never alone a deceive trigger */
    public $anomaly;

    /** @var BotSignalSet computed request-shape signals; INPUT-side only, never emitted */
    public $signals;

    /** @var FakeHandle|null pointer to what synthesize() would build; null when nothing to fake */
    public $fakeHandle;

    public function __construct(
        string $classification,
        Detection $detection,
        string $severity = '',
        int $anomaly = 0,
        ?BotSignalSet $signals = null,
        ?FakeHandle $fakeHandle = null
    ) {
        $this->classification = $classification;
        $this->detection = $detection;
        $this->severity = $severity;
        $this->anomaly = $anomaly;
        $this->signals = $signals ?? BotSignalSet::empty();
        $this->fakeHandle = $fakeHandle;
    }

    /** A clean verdict carrying only the computed signals (no route, no attack). */
    public static function clean(?BotSignalSet $signals = null): self
    {
        $set = $signals ?? BotSignalSet::empty();

        return new self(self::CLEAN, Detection::none(), '', $set->weight, $set, null);
    }

    public function isClean(): bool
    {
        return $this->classification === self::CLEAN;
    }

    public function isAmbient(): bool
    {
        return $this->classification === self::AMBIENT;
    }

    /**
     * Pure-data projection for logging / telemetry (decision T). Detection is folded to its
     * ids + tags so the whole array is serializable.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'classification' => $this->classification,
            'severity' => $this->severity,
            'anomaly' => $this->anomaly,
            'signals' => $this->signals->toArray(),
            'fakeHandle' => $this->fakeHandle === null ? null : $this->fakeHandle->toArray(),
            'detection' => [
                'matched' => $this->detection->matched,
                'templateIds' => $this->detection->templateIds(),
                'tags' => $this->detection->tags(),
                'clusterKey' => $this->detection->clusterKey,
                'highestSeverity' => $this->detection->highestSeverity,
            ],
        ];
    }
}
