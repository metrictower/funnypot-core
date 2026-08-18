<?php

declare(strict_types=1);

namespace Funnypot\Store;

use Funnypot\Contracts\CompiledStore;
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
    private array $routes;

    /** @var array<string,mixed> */
    private array $templates;

    /** @var array<string,mixed> */
    private array $manifest;

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
    private static array $fileCache = [];

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
     * Load the full prebuilt index shipped with the package (the real ~5k-template
     * artifact produced by the compiler). `nuclei-index.php` alongside it is a small
     * hand-written fixture used only by unit tests, not this.
     */
    public static function fromPackage(): self
    {
        return self::fromFile(dirname(__DIR__, 2) . '/resources/compiled/nuclei-index.full.php');
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
