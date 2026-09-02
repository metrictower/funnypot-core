<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * OPTIONAL push seam for the boot-time seed-health signal (FP-0276). An Observer that ALSO implements
 * this interface is handed the deploy's Support\SeedHealth report ONCE, at engine construction — so an
 * operator dashboard or boot log can surface an unseeded/fleet-constant install without polling.
 *
 * Deliberately a SEPARATE interface, not a method on Observer: adding to Observer would break every
 * existing app implementer. It is fired inside a try/catch (FP-0252 swallow discipline) so a throwing
 * implementation can never change served bytes or fail construction. The report is a non-served health
 * signal and MUST NOT enter any SynthesizedResponse.
 *
 * Cadence note: the shipped app builds the engine PER REQUEST, so a per-request engine construction
 * fires onSeedHealth() per request; the app is expected to dedupe (e.g. log once per boot). The pull
 * API Honeypot::seedHealth() is the primary path (no Observer needed) and is what an app status page
 * reads; push stays opt-in via this interface for hosts that want it.
 */
interface HealthObserver
{
    /**
     * @param array{identity:string,render_salt:string,ok:bool,warnings:list<string>} $report
     *        the same array Config::seedHealth() / Honeypot::seedHealth() return.
     */
    public function onSeedHealth(array $report): void;
}
