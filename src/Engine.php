<?php

declare(strict_types=1);

namespace Funnypot;

use Funnypot\Contracts\Evaluator;

/**
 * The package's contract. The forward-looking shape is the two-phase Evaluator port
 * (classify + synthesize) — position-blind and action-free. detect()/respond() are retained as
 * a LEGACY facade over that port so the existing app keeps working until it migrates to
 * funnypot-policy; new consumers use classify()/synthesize() (via the policy).
 */
interface Engine extends Evaluator
{
    /**
     * LEGACY. Signal whether an incoming request matches a known scanner probe. Never null;
     * Detection::none() on a miss. Shim over classify($r, SiteProfile::empty())->detection.
     */
    public function detect(RequestContext $r): Detection;

    /**
     * LEGACY back-compat facade over classify()+synthesize() with the old Config gates + Observer
     * layered on. Synthesize the response the matched template(s) expect, or null when nothing
     * should be served (miss, gate closed, or respond mode disabled).
     */
    public function respond(RequestContext $r): ?SynthesizedResponse;
}
