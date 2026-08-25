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
 * OPCACHE IS A HARD OPERATING REQUIREMENT, not an optimisation. The file being a pure literal is
 * what lets opcache intern it as an immutable array, shared across workers at no per-process cost.
 * Without opcache the index is re-materialised on EVERY request — per request, not per worker,
 * because the static below dies at request shutdown. Measured across PHP 7.3/8.0/8.4/8.5:
 *
 *   opcache on   0.00 MB process heap per request,  ~0.9 MB private per worker
 *   opcache off  20.43 MB process heap per request, ~42 MB private per worker
 *
 * Two ways to lose the interning silently, both worth guarding in review:
 *   - making the compiled artifact non-literal (a const reference, a function call, a computed key)
 *   - opcache.file_cache_only=1, which loads into process memory and reinstates the full cost
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
        // Dedupe the index WITHIN one request. This static is destroyed at request shutdown in
        // every per-request SAPI, php-fpm included, so it does NOT persist across requests there —
        // only a true long-lived worker (RoadRunner, Swoole) keeps it between requests.
        //
        // What actually makes this cheap under php-fpm is opcache: the compiled file is a pure
        // literal, so opcache interns it into shared memory as an immutable array, and immutable
        // arrays are not refcounted — passing one through this static, the constructor and the
        // object properties never copies it. Measured: 0.00 MB of process heap per request with
        // opcache on, 20.43 MB per request with it off. Restart the worker to pick up a recompiled
        // index.
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

    /**
     * Is the compiled index actually shared, or is every request re-materialising it?
     *
     * The cost difference is 0.00 MB vs 20.43 MB of process heap PER REQUEST, and nothing else
     * tells you which side of that you are on — a misconfigured host looks identical to a correct
     * one until it runs out of memory under load. Call this from a health check or a doctor
     * command; never throw on the result, because a dev box legitimately runs without opcache.
     *
     * @param string|null $path defaults to the packaged index
     * @return array{shared:bool,reason:string,remedy:string,sapi:string,shm_free:int,restarts:int}
     */
    public static function diagnose(?string $path = null): array
    {
        $path = $path ?? RulesLocator::resolve('nuclei-index.full.php');
        $sapi = PHP_SAPI;

        $out = [
            'shared' => false,
            'reason' => 'unknown',
            'remedy' => '',
            'sapi' => $sapi,
            'shm_free' => 0,
            'restarts' => 0,
        ];

        if (!function_exists('opcache_get_status') || !function_exists('opcache_is_script_cached')) {
            $out['reason'] = 'opcache extension not loaded';
            $out['remedy'] = 'Install and enable Zend OPcache. Without it the index costs ~20 MB of heap on every request.';

            return $out;
        }

        // CLI is gated by opcache.enable_cli; every other SAPI by opcache.enable. Note `php -S`
        // reports "cli-server" and is gated by opcache.enable, NOT enable_cli.
        $flag = $sapi === 'cli' ? 'opcache.enable_cli' : 'opcache.enable';
        if (!filter_var(ini_get($flag), FILTER_VALIDATE_BOOLEAN)) {
            $out['reason'] = $flag . ' is off';
            $out['remedy'] = 'Set ' . $flag . '=1.'
                . ($sapi === 'cli' ? ' CLI opcache is off by default, so queue workers pay full cost per process.' : '');

            return $out;
        }

        // file_cache_only loads into process memory, silently reinstating the full per-request cost.
        if (filter_var(ini_get('opcache.file_cache_only'), FILTER_VALIDATE_BOOLEAN)) {
            $out['reason'] = 'opcache.file_cache_only is on, so nothing is interned into shared memory';
            $out['remedy'] = 'Set opcache.file_cache_only=0.';

            return $out;
        }

        // opcache.restrict_api can make these fail for the calling script; degrade rather than throw.
        try {
            // Deliberately opcache_get_status(FALSE): the true form materialises every cached
            // script, which on a large app is far more expensive than this check is worth.
            $status = opcache_get_status(false);
            $cached = opcache_is_script_cached($path);
        } catch (\Throwable $e) {
            $out['reason'] = 'opcache API unavailable (opcache.restrict_api?): ' . $e->getMessage();
            $out['remedy'] = 'Allow this script under opcache.restrict_api, or check the host another way.';

            return $out;
        }

        if (is_array($status)) {
            $out['shm_free'] = (int) ($status['memory_usage']['free_memory'] ?? 0);
            $out['restarts'] = (int) ($status['opcache_statistics']['oom_restarts'] ?? 0)
                + (int) ($status['opcache_statistics']['hash_restarts'] ?? 0);
        }

        if (!$cached) {
            $out['reason'] = 'the compiled index is not in opcache';
            $out['remedy'] = 'Usually shared memory is full or the file-count cap is hit — raise'
                . ' opcache.memory_consumption and opcache.max_accelerated_files above what the host app already uses.';

            return $out;
        }

        $out['shared'] = true;
        $out['reason'] = 'interned into opcache shared memory';

        if ($out['restarts'] > 0) {
            $out['remedy'] = 'Interned now, but opcache has restarted ' . $out['restarts']
                . ' time(s) — it is being evicted under pressure. Raise opcache.memory_consumption.';
        }

        return $out;
    }
}
