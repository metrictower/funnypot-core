<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * App-policy seam. The core calls these on the respond() path so all logging,
 * scoring, and banning live in the host app — the core stays side-effect-free.
 */
interface Observer
{
    /**
     * A request routed to a known scanner probe. Fires even when respond() then
     * declines to serve (gate closed, severity capped, etc.), so the app can score
     * the probe regardless of whether a fake is served.
     */
    public function onDetection(RequestContext $r, Detection $detection): void;

    /**
     * App veto: return false to suppress serving a fake even when every gate passed.
     */
    public function shouldRespond(RequestContext $r, Detection $detection): bool;

    /**
     * Outcome of the respond() path once a probe matched: whether a fake was served
     * and, if not, why (an Outcome::* constant). Lets the app measure poisoning
     * coverage without wrapping the emitter. $response is null on every non-served
     * outcome. Core does no I/O — it only calls this.
     */
    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void;
}
