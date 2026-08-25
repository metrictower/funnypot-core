<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * A read-only snapshot of the installed rule set — what `rules:status` prints and what a
 * staleness alarm reads. `source` is 'data-dir' when a RulesUpdater-managed release is live,
 * 'bundled' when the packaged floor is serving (never updated, or the data dir self-healed).
 */
final class RulesStatus
{
    /** @var string */
    public $source;

    /** @var string|null */
    public $version;

    /** @var int|null */
    public $versionSeq;

    /** @var string|null */
    public $appliedAt;

    /** @var string|null */
    public $checkedAt;

    /** @var array<string,int> */
    public $coverage;

    /** @var string[] versions retained on disk for network-free rollback */
    public $retained;

    /**
     * @param array<string,int> $coverage
     * @param string[]          $retained
     */
    public function __construct(
        string $source,
        ?string $version,
        ?int $versionSeq,
        ?string $appliedAt,
        ?string $checkedAt,
        array $coverage,
        array $retained
    ) {
        $this->source = $source;
        $this->version = $version;
        $this->versionSeq = $versionSeq;
        $this->appliedAt = $appliedAt;
        $this->checkedAt = $checkedAt;
        $this->coverage = $coverage;
        $this->retained = $retained;
    }

    /**
     * Seconds since the last successful contact with upstream (a verified fetch, whether it
     * swapped or was already current), falling back to the last apply. This is what a
     * staleness alarm keys off: a wedged updater stops advancing checked_at and goes blind.
     */
    public function ageSeconds(?int $now = null): ?int
    {
        $stamp = $this->checkedAt ?? $this->appliedAt;
        if ($stamp === null) {
            return null;
        }
        $ts = strtotime($stamp);
        if ($ts === false) {
            return null;
        }

        return max(0, ($now ?? time()) - $ts);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'version' => $this->version,
            'version_seq' => $this->versionSeq,
            'applied_at' => $this->appliedAt,
            'checked_at' => $this->checkedAt,
            'coverage' => $this->coverage,
            'retained' => $this->retained,
        ];
    }
}
