<?php

declare(strict_types=1);

namespace Funnypot\Contracts;

/**
 * Read access to the compiled template index. Default implementation is a literal
 * PHP array frozen by opcache; a SQLite variant can back memory-constrained hosts.
 */
interface CompiledStore
{
    /**
     * Look up a routing key ("METHOD /path"). Returns the route entry
     * (`['b' => [ ...bundles... ]]`) or null on a miss.
     *
     * @return array<string,mixed>|null
     */
    public function lookup(string $key): ?array;

    /**
     * Metadata for a template id: ['sev' => string, 'tags' => string[], 'name' => string].
     *
     * @return array<string,mixed>|null
     */
    public function template(string $id): ?array;

    /**
     * Manifest info: schema version, upstream tag/sha, build time, counts.
     *
     * @return array<string,mixed>
     */
    public function version(): array;
}
