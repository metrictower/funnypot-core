<?php

declare(strict_types=1);

namespace Funnypot\Behavior;

use Funnypot\Contracts\Clock;

/** The default Clock: the host's real wall clock. */
final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}
