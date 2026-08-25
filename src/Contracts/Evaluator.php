<?php

declare(strict_types=1);

namespace Funnypot\Core\Contracts;

use Funnypot\Core\FakeHandle;
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

    /**
     * Same as synthesize(), but from the Verdict's FakeHandle alone.
     *
     * synthesize() reads NOTHING off the Verdict except its handle, and FakeHandle is opaque and
     * serializable by design — so a caller that cannot keep the Verdict object alive between the
     * two phases can carry the handle instead. Guaranteed to produce the byte-identical response
     * `synthesize()` would have, given the same handle, profile and seed.
     *
     * This exists because the phases are separated by a boundary in practice: an adapter maps
     * core's Verdict into another package's own Verdict type, and that type cannot carry a core
     * object. Without this, adapters either memoise (needs WeakMap, so PHP 8.0+, which rules out
     * the 7.3 hosts this package supports) or re-run classify() and pay for it twice. Both were
     * being done, in different adapters, for the same contract.
     *
     * A null handle degrades to null, exactly as a Verdict with no handle does.
     */
    public function synthesizeFromHandle(?FakeHandle $handle, SiteProfile $profile, string $seed): ?SynthesizedResponse;
}
