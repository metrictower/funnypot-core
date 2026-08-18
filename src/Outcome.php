<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Why the respond() path ended, reported to the observer once a probe has matched.
 * (kill switch / mode / trusted bypass / route miss short-circuit BEFORE a probe is
 * recognized, so they never reach the observer.) String constants, not an enum, for
 * PHP 8.0.
 */
final class Outcome
{
    public const SERVED = 'served';
    public const GATE_CLOSED = 'gate-closed';
    public const NO_CANDIDATE = 'no-candidate'; // all bundles excluded or above the severity ceiling
    public const NO_SIGNATURE = 'no-signature'; // sig=1 root without a probe signature
    public const VETOED = 'vetoed';             // observer.shouldRespond returned false
    public const OVER_CAP = 'over-cap';         // synthesized body exceeded maxBodyBytes
    public const UNSYNTHESIZABLE = 'unsynthesizable'; // synth out of scope for this bundle
}
