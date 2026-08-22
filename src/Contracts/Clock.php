<?php

declare(strict_types=1);

namespace Funnypot\Contracts;

/**
 * Wall-clock source for behavior primitives that need the current time (e.g. a delay signal).
 * Injected so tests can freeze time; the default host binding reads the real clock.
 */
interface Clock
{
    /** Current Unix time in whole seconds. */
    public function now(): int;
}
