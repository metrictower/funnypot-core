<?php

declare(strict_types=1);

namespace Funnypot\Core\Contracts;

use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Verdict;

/**
 * The position-blind, action-free two-phase engine port (two-phase design §4 / decision M2).
 *
 * classify() is content-detection only — cheap, always safe, no I/O, no gates. synthesize() owns
 * the deception content and is invoked ONLY once the caller's policy has chosen to deceive; core
 * never decides that. SiteProfile (declared stack + real-route oracle) and the deterministic seed
 * flow in as DATA, so the same engine serves every position×action combo without a code change.
 *
 * funnypot-policy declares its own `Port\EvaluatorInterface` in policy-namespace types; a thin
 * host adapter bridges core's native types to it (design §1 / §4). This core-side port keeps the
 * engine buildable standalone — core takes no dependency on the policy package.
 */
interface Evaluator
{
    /**
     * What is this request, as content? Never "should we act?". No side effects, no I/O.
     */
    public function classify(RequestContext $r, SiteProfile $profile): Verdict;

    /**
     * Build the fake a Verdict points at, or null to degrade to the caller's 404 (the engine only
     * ever upgrades a 404, never emits a 5xx). Pure function of (verdict, profile, seed) + store.
     */
    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?SynthesizedResponse;
}
