<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * App-policy seam. The core calls these on the respond() path so all logging,
 * scoring, and banning live in the host app — the core stays side-effect-free.
 *
 * Fail-safe contract (FP-0252): the core wraps every call below in try/catch and
 * SWALLOWS any Throwable, so a bug in your implementation can never turn a request
 * into a host 500. A throw is therefore NOT a veto: to suppress a fake, return false
 * from shouldRespond() — do not throw/abort() from onDetection() (that exception is
 * discarded and the fake is still served). A shouldRespond() throw is treated as a
 * veto (Outcome::VETOED); onDetection()/onOutcome() throws are silently dropped.
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
