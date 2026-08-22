<?php

declare(strict_types=1);

namespace Funnypot\Contracts;

/**
 * Small per-actor scratch space for behavior primitives that fake continuity across a
 * short burst of requests (e.g. a session oracle). Values are ephemeral: a real impl MUST
 * bound its entry count and evict LRU, so a flood of distinct keys can never grow it without
 * limit — the store is attacker-reachable. The real bounded impl is deferred (session-oracle
 * milestone); until then the null impl below is the safe default.
 */
interface EphemeralStore
{
    /** The stored value for $key, or null when absent/expired. */
    public function get(string $key): ?string;

    /** Store $value under $key; $ttlSeconds 0 means the impl's default lifetime. */
    public function put(string $key, string $value, int $ttlSeconds = 0): void;
}
