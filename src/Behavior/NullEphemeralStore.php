<?php

declare(strict_types=1);

namespace Funnypot\Behavior;

use Funnypot\Contracts\EphemeralStore;

/**
 * The safe default EphemeralStore: remembers nothing. get() is always a miss and put() is a
 * no-op, so a primitive that consults the store degrades to its stateless behavior. NOT a real
 * store — the bounded, LRU-evicting impl is deferred to the session-oracle milestone.
 */
final class NullEphemeralStore implements EphemeralStore
{
    public function get(string $key): ?string
    {
        return null;
    }

    public function put(string $key, string $value, int $ttlSeconds = 0): void
    {
        // Intentionally empty: the null store keeps no state.
    }
}
