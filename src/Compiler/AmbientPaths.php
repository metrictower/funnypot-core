<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Support\PathNormalizer;
use RuntimeException;

/**
 * Build-time: the curated ambient-path list (resources/ambient-paths.php) — paths a site is asked
 * for whether or not it has them. Both halves of the build stamp amb=1 from it: the corpus
 * compiler on every bundle at a curated key, the new-page fragment synth on every folded bundle at
 * a curated key. One list, one keying rule, so the two halves can never disagree at a key.
 */
final class AmbientPaths
{
    /**
     * Fails closed on a missing or empty resource: a silent empty list compiles a working-looking
     * artifact that reports every browser's favicon fetch again.
     *
     * @return string[]
     */
    public static function fromPackage(): array
    {
        $file = dirname(__DIR__, 2) . '/resources/ambient-paths.php';
        if (!is_file($file)) {
            throw new RuntimeException('Ambient-path resource missing: ' . $file);
        }
        $paths = require $file;
        if (!is_array($paths) || $paths === []) {
            throw new RuntimeException('Ambient-path list is empty or malformed — refusing to compile with no ambient paths.');
        }

        return array_values(array_map('strval', $paths));
    }

    /**
     * GET-only route keys for a path list. Exact keys via PathNormalizer::key() — never a prefix
     * or substring rule (/actuator/favicon.ico and /web/manifest.json are real probes).
     *
     * @param string[] $paths
     * @return array<string,true>
     */
    public static function routeKeys(array $paths): array
    {
        $keys = [];
        foreach ($paths as $p) {
            $keys[PathNormalizer::key('GET', (string) $p)] = true;
        }

        return $keys;
    }
}
