<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use RuntimeException;

/**
 * Deterministic input-tree provenance: a single sha256 over the exact set of input files a
 * compile step read, each contributing its repo-relative path and a sha256 of its bytes.
 *
 * This is the field that replaces `built_at` in the compiled index (a wall-clock stamp made a
 * fresh recompile never reproduce the committed bytes; this one is a pure function of the
 * inputs, so the zero-drift gate can recompute it). Two rules keep it stable across machines:
 *
 *   - Paths are repo-relative and `/`-separated, sorted SORT_STRING — never absolute (which
 *     carries the build machine's `/home/...`) and never OS-slash-dependent.
 *   - Only the files a step actually GLOBS are hashed (pass TemplateGlob output), never "every
 *     file in the dir" — so a `.DS_Store` or an editor swap file can't spuriously change it.
 *
 * Line-ending stability (a CRLF checkout would change every file's byte-hash) is enforced out
 * of band by `.gitattributes` (`*.yaml`/`*.php text eol=lf`), not by normalising here — hashing
 * the real bytes keeps the stamp independent of git internals.
 */
final class SourceTreeStamp
{
    /**
     * @param string[] $files absolute paths of the input files (e.g. TemplateGlob::yaml($dirs))
     * @param string   $root  repo root the paths are made relative to
     */
    public static function hash(array $files, string $root): string
    {
        $root = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $rows = [];
        foreach ($files as $file) {
            $abs = str_replace('\\', '/', $file);
            $rel = strncmp($abs, $root, strlen($root)) === 0 ? substr($abs, strlen($root)) : $abs;
            $bytes = @file_get_contents($file);
            if ($bytes === false) {
                throw new RuntimeException("SourceTreeStamp: cannot read input file: {$file}");
            }
            $rows[] = $rel . "\0" . hash('sha256', $bytes) . "\n";
        }
        // The file list is already SORT_STRING-ordered by TemplateGlob, but sort the rows too so
        // the stamp is order-independent of however the caller assembled $files.
        sort($rows, SORT_STRING);

        return hash('sha256', implode('', $rows));
    }
}
