<?php

declare(strict_types=1);

namespace Funnypot\Support;

/**
 * nuclei severity ordering, shared by the detection ceiling and the respond-mode
 * severity gate.
 */
final class Severity
{
    private const RANK = [
        'unknown' => 0,
        'info' => 1,
        'low' => 2,
        'medium' => 3,
        'high' => 4,
        'critical' => 5,
    ];

    public static function rank(string $severity): int
    {
        return self::RANK[strtolower($severity)] ?? 0;
    }

    /**
     * True when $severity is stronger than $ceiling (so respond mode should refuse
     * to fabricate it under a severity cap).
     */
    public static function exceeds(string $severity, string $ceiling): bool
    {
        return self::rank($severity) > self::rank($ceiling);
    }

    public static function ceiling(string $a, string $b): string
    {
        return self::rank($a) >= self::rank($b) ? $a : $b;
    }
}
