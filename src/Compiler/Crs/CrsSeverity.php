<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Crs;

/**
 * Maps a CRS severity token onto funnypot's severity vocabulary.
 *
 * CRITICAL maps to `high`, not `critical`, on purpose: funnypot's default severityCeiling
 * is `high`, and the mapping must respect that default so an import never silently fabricates
 * a class the operator has not opted into. The class archetype supplies a per-class floor
 * (see CrsArchetypes) so a class that funnypot keeps gated — e.g. fake RCE — stays gated.
 */
final class CrsSeverity
{
    public static function map(string $crs): string
    {
        switch (strtoupper(trim($crs))) {
            case 'CRITICAL':
                return 'high';
            case 'ERROR':
                return 'medium';
            case 'WARNING':
                return 'low';
            case 'NOTICE':
            case 'INFO':
                return 'low';
            default:
                return 'low';
        }
    }
}
