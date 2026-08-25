<?php

declare(strict_types=1);

namespace Funnypot\Core\Store;

use Funnypot\Core\Contracts\CompiledStore;
use Funnypot\Core\Rules\RulesLocator;
use InvalidArgumentException;

/**
 * Default store: a single literal PHP array compiled to disk and frozen by
 * opcache into shared memory. Lookup is one hash probe; a miss is the same probe
 * returning null. No extensions required.
 *
 * Compiled file shape:
 *   [
 *     'schema'    => 1,
 *     'manifest'  => [ ...upstream tag/sha, counts... ],
 *     'templates' => [ 'git-config' => ['sev'=>'medium','tags'=>[...],'name'=>...], ... ],
 *     'routes'    => [ 'GET /.git/config' => ['b' => [ ...bundles... ]], ... ],
 *   ]
 */
final class PhpArrayStore implements CompiledStore
{
    /** @var array<string,mixed> */
    private $routes;

    /** @var array<string,mixed> */
    private $templates;

    /** @var array<string,mixed> */
    private $manifest;

    /** @param array<string,mixed> $index */
    public function __construct(array $index)
    {
        if (($index['schema'] ?? null) !== 1) {
            throw new InvalidArgumentException('Unsupported compiled-index schema.');
        }

        $this->routes = $index['routes'] ?? [];
        $this->templates = $index['templates'] ?? [];
        $this->manifest = $index['manifest'] ?? [];
    }

    /** @var array<string,array<string,mixed>> parsed index cache, keyed by path */
    private static $fileCache = [];

    public static function fromFile(string $path): self
    {
        // Cache the parsed index per path for the life of the process. The compiled
        // file is multi-megabyte, so under a persistent worker (php-fpm, RoadRunner)
        // this loads it ONCE per worker instead of re-materializing it per request —
        // the difference between surviving a scanner's request flood and timing out.
        // Restart the worker to pick up a recompiled index.
        if (!isset(self::$fileCache[$path])) {
            if (!is_file($path)) {
                throw new InvalidArgumentException("Compiled index not found: {$path}");
            }

            /** @var mixed $index */
            $index = require $path;

            if (!is_array($index)) {
                throw new InvalidArgumentException("Compiled index did not return an array: {$path}");
            }

            self::$fileCache[$path] = $index;
        }

        return new self(self::$fileCache[$path]);
    }

    /**
     * Load the full prebuilt index. RulesLocator prefers a RulesUpdater-managed copy under
     * the configured data dir and otherwise returns the artifact shipped with the package
     * (the real ~5k-template artifact produced by the compiler). `nuclei-index.php` alongside
     * it is a small hand-written fixture used only by unit tests, not this.
     */
    public static function fromPackage(): self
    {
        return self::fromFile(RulesLocator::resolve('nuclei-index.full.php'));
    }

    /**
     * Drop the parsed-index cache for $path (or all paths). Called by RulesUpdater right
     * after an atomic swap so a long-lived worker stops serving the pre-swap array — a
     * rename alone does not evict this in-process cache.
     */
    public static function forget(?string $path = null): void
    {
        if ($path === null) {
            self::$fileCache = [];

            return;
        }

        unset(self::$fileCache[$path]);
    }

    public function lookup(string $key): ?array
    {
        return $this->routes[$key] ?? null;
    }

    public function template(string $id): ?array
    {
        return $this->templates[$id] ?? null;
    }

    public function version(): array
    {
        return $this->manifest;
    }
}
