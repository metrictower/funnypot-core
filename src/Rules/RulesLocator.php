<?php

declare(strict_types=1);

namespace Funnypot\Rules;

/**
 * Resolves where a compiled rule artifact is loaded from, so a running honeypot can
 * pick up a fresher, RulesUpdater-managed rule set without a composer update — while
 * a host that never opts in behaves byte-identically to before this class existed.
 *
 * Resolution order for a bare artifact name (e.g. "nuclei-index.full.php"):
 *   1. If a data dir is configured (RulesLocator::useDataDir() or env FUNNYPOT_RULES_DIR)
 *      and "<dataDir>/current/<artifact>" is a readable file, return that path.
 *   2. Otherwise the artifact bundled inside the package — today's behaviour, always present.
 *
 * Step 1 uses is_file(), which follows the `current` symlink and returns false for a
 * dangling one, so an interrupted swap or a manually-deleted data dir self-heals to the
 * bundled floor on the very NEXT resolution — the offline/fail-safe guarantee, mechanical
 * rather than by policy. Resolution runs on every load, not once at boot.
 *
 * This is a path chooser, not a trust boundary. The bytes under `current/` are trusted
 * because RulesUpdater is the only writer and it verifies (ed25519 signature + per-file
 * sha256 + PhpLiteralValidator) before it ever renames a release into place. Nothing here
 * re-tokenises a multi-megabyte artifact per worker boot.
 */
final class RulesLocator
{
    /** @var string|null Process-global data-dir override, set by the Laravel bridge or tests. Null = use env. */
    private static $dataDir = null;

    /** @var bool True once useDataDir() has been called, so an explicit null override wins over env. */
    private static $overridden = false;

    /**
     * Point resolution at a data dir for this process (or pass null to force the bundled
     * floor regardless of environment). The Laravel bridge calls this from its config; tests
     * call it to redirect and then reset. Call reset() to fall back to env again.
     */
    public static function useDataDir(?string $dir): void
    {
        self::$dataDir = ($dir === null || $dir === '') ? null : rtrim($dir, '/');
        self::$overridden = true;
    }

    /** Drop any override so resolution consults FUNNYPOT_RULES_DIR again. */
    public static function reset(): void
    {
        self::$dataDir = null;
        self::$overridden = false;
    }

    /**
     * The configured data dir, or null when none is set (the entire installed base today).
     * An explicit override — including an explicit null — wins over the environment.
     */
    public static function dataDir(): ?string
    {
        if (self::$overridden) {
            return self::$dataDir;
        }

        $env = getenv('FUNNYPOT_RULES_DIR');

        return is_string($env) && $env !== '' ? rtrim($env, '/') : null;
    }

    /**
     * Absolute path to load $artifact (a bare compiled-artifact filename) from.
     *
     * @param string $artifact e.g. "nuclei-index.full.php" — a filename, never a path
     */
    public static function resolve(string $artifact): string
    {
        // Only ever a leaf name is permitted; a caller passing a path would let the data-dir
        // override reach outside `current/`. Fall back to the packaged copy of the leaf name.
        $artifact = basename($artifact);

        $dataDir = self::dataDir();
        if ($dataDir !== null) {
            $candidate = $dataDir . '/current/' . $artifact;
            // is_file() follows the `current` symlink; false for a dangling link or a missing
            // file, so we self-heal to the bundled floor rather than error.
            if (is_file($candidate) && is_readable($candidate)) {
                return $candidate;
            }
        }

        return self::packagedPath($artifact);
    }

    /** The path the fromPackage() loaders used before this seam existed. */
    public static function packagedPath(string $artifact): string
    {
        return dirname(__DIR__, 2) . '/resources/compiled/' . basename($artifact);
    }
}
