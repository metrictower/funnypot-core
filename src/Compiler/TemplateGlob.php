<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use RuntimeException;

/**
 * The single source of truth for "which template files does a compile step read?".
 *
 * Every compile-* step globs `*.yaml` out of one or more dirs; this centralises that glob so
 * (a) the ordering is one fixed, cross-PHP-stable rule (SORT_STRING — never SORT_REGULAR, whose
 * digit-prefixed-filename comparison semantics shifted between PHP 7 and 8), and (b) the exact
 * file set a step compiles is the same set its `source_tree` provenance stamp hashes (see
 * SourceTreeStamp) — so the stamp can never drift from the bytes it claims to describe.
 *
 * A stray `*.yml` (the other YAML extension) is a build failure, not a silent drop: the globs
 * only ever matched `*.yaml`, so a `.yml` template would compile to nothing with no warning.
 */
final class TemplateGlob
{
    /**
     * The sorted (SORT_STRING) list of `*.yaml` files across the given dirs. Missing dirs are
     * skipped (a step folds optional sibling dirs — attack-crs, attack-ai, generated — that may
     * not exist yet). Throws if any dir carries a `*.yml` file.
     *
     * @param string[] $dirs
     * @return string[]
     */
    public static function yaml(array $dirs): array
    {
        $files = [];
        foreach ($dirs as $dir) {
            $base = rtrim($dir, '/');
            $stray = glob($base . '/*.yml') ?: [];
            if ($stray !== []) {
                throw new RuntimeException(
                    "Stray *.yml template(s) in {$base} (compilers glob *.yaml only, so these would be silently ignored): "
                    . implode(', ', array_map('basename', $stray))
                );
            }
            foreach (glob($base . '/*.yaml') ?: [] as $file) {
                $files[] = $file;
            }
        }
        sort($files, SORT_STRING);

        return $files;
    }
}
