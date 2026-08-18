<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * The package's contract. `mode` (off/detect/respond) is a wiring concern of the
 * caller: detect() is always safe to call; respond() honours gating and returns
 * null when the app should serve its own 404.
 */
interface Engine
{
    /**
     * Signal whether an incoming request matches a known scanner probe. Never null;
     * Detection::none() on a miss.
     */
    public function detect(RequestContext $r): Detection;

    /**
     * Synthesize the response the matched template(s) expect, or null when nothing
     * should be served (miss, gate closed, or respond mode disabled).
     */
    public function respond(RequestContext $r): ?SynthesizedResponse;
}
