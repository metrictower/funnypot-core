<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Result of detect mode: which known scanner probe(s) an incoming request maps to.
 *
 * Signal only — no side effects. The app decides what to do with it (score, ban,
 * log, or escalate to respond mode).
 */
final class Detection
{
    /** nuclei severities, low to high, for picking the ceiling of a match set. */
    private const SEVERITY_RANK = [
        'unknown' => 0,
        'info' => 1,
        'low' => 2,
        'medium' => 3,
        'high' => 4,
        'critical' => 5,
    ];

    /** @var bool */
    public $matched;

    /** @var TemplateMatch[] */
    public $matches;

    /** @var string */
    public $clusterKey;

    /** @var string */
    public $highestSeverity;

    /** @param TemplateMatch[] $matches */
    public function __construct(
        bool $matched,
        array $matches = [],
        string $clusterKey = '',
        string $highestSeverity = ''
    ) {
        $this->matched = $matched;
        $this->matches = $matches;
        $this->clusterKey = $clusterKey;
        $this->highestSeverity = $highestSeverity;
    }

    public static function none(): self
    {
        return new self(false, [], '', '');
    }

    public function isEmpty(): bool
    {
        return !$this->matched || $this->matches === [];
    }

    /** @return string[] */
    public function templateIds(): array
    {
        return array_map(static function (TemplateMatch $m): string {
            return $m->id;
        }, $this->matches);
    }

    /** @return string[] */
    public function tags(): array
    {
        $tags = [];
        foreach ($this->matches as $match) {
            foreach ($match->tags as $tag) {
                $tags[$tag] = true;
            }
        }

        return array_keys($tags);
    }

    /**
     * Highest severity across the match set, by nuclei's ordering.
     */
    public static function ceilingSeverity(string $a, string $b): string
    {
        $ra = self::SEVERITY_RANK[$a] ?? 0;
        $rb = self::SEVERITY_RANK[$b] ?? 0;

        return $ra >= $rb ? $a : $b;
    }
}
