<?php

declare(strict_types=1);

namespace Funnypot\Support;

/**
 * Turns an incoming request path into the routing key path.
 *
 * BYTE-IDENTITY on the raw request-target. Scanners probe exact byte sequences
 * (mixed-case percent-escapes like %2F/%2f, traversal like ..%2F.., invalid
 * UTF-8 like /%c0). If we decode, lowercase, or collapse those, the runtime key
 * diverges from the compiled key and the probe misses. So we ONLY:
 *   - drop the query string (recorded separately as a discriminator)
 *   - guarantee a single leading slash
 * We do NOT percent-decode, lowercase, or resolve "..".
 */
final class PathNormalizer
{
    public static function normalize(string $path): string
    {
        // Defensive: strip a query if a caller passed a full request-target.
        $qpos = strpos($path, '?');
        if ($qpos !== false) {
            $path = substr($path, 0, $qpos);
        }

        // Strip a fragment if present (never sent by clients, but be safe).
        $hpos = strpos($path, '#');
        if ($hpos !== false) {
            $path = substr($path, 0, $hpos);
        }

        if ($path === '') {
            return '/';
        }

        if ($path[0] !== '/') {
            $path = '/' . $path;
        }

        return $path;
    }

    /**
     * Canonical ownership key: the form the attack-tier path-override set is keyed on. Lower-cases
     * and strips a trailing slash (except root) so the case/trailing-slash variants resolveEntry can
     * hit the store with all collapse to one key. Never lower-cases inside normalize() itself —
     * resolveEntry relies on the case-preserving normalize.
     */
    public static function ownershipKey(string $path): string
    {
        $n = strtolower(self::normalize($path));
        if ($n !== '/' && substr($n, -1) === '/') {
            $n = rtrim($n, '/');
        }

        return $n;
    }

    /**
     * Compiled routing key: "METHOD normalized-path". Method upper-cased; path
     * kept byte-identical.
     */
    public static function key(string $method, string $path): string
    {
        return strtoupper($method) . ' ' . self::normalize($path);
    }
}
