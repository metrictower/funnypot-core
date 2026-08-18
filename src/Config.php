<?php

declare(strict_types=1);

namespace Funnypot;

use Closure;
use Funnypot\Response\Style;

/**
 * Host-app policy for the inverter. Defaults make an install INERT: detect mode
 * only, respond gate closed. The app opts in by raising `mode` to 'respond' and
 * supplying a `gate` predicate.
 *
 * The closure knobs are `?Closure` so callers pass `fn (...) => ...`. All are
 * side-effect-free predicates the core calls; the core never does I/O itself.
 */
final class Config
{
    /**
     * @param string        $mode            off | detect | respond
     * @param Closure|null  $gate            fn(RequestContext):bool — app suspicion predicate; null ⇒ closed (false)
     * @param string        $pathScope       matched-only (only compiled paths) | any
     * @param Closure|null  $personaSeed     fn(RequestContext):string — determinism source; null ⇒ host + salt
     * @param string        $personaBreadth  coherent (one product persona) | greedy
     * @param string        $responseStyle   minimal | realistic | taunt (see Response\Style)
     * @param string        $severityCeiling refuse to fabricate anything stronger than this
     * @param int           $maxBodyBytes    hard cap; a larger synthesized body is refused
     * @param int           $latencyMs       optional tarpit delay applied by the emitter, never the core
     * @param Closure|null  $trustedBypass   fn(RequestContext):bool — own scanners; true ⇒ never serve fakes
     * @param Closure|null  $killSwitch      fn():bool — true ⇒ respond disabled (un-poison)
     * @param Closure|null  $probeSignature  fn(RequestContext):bool — root/homepage (sig=1) fires ONLY when true; null ⇒ never
     * @param string        $seedSalt        per-deploy salt so persona differs per site
     * @param string[]      $exclude         template ids or tags to never serve
     * @param bool          $nucleiReflection false drops every nuclei-corpus fake (discrete attack
     *                                        and route emulations still serve); the app's emulation
     *                                        catalog toggle drives this
     * @param string|null   $serverHeader    Server banner emitted on EVERY response, so one host
     *                                       presents one coherent server identity (anti-fingerprint).
     *                                       null ⇒ don't force one.
     * @param string|null   $poweredBy       X-Powered-By emitted on every response, consistent with
     *                                       $serverHeader. null ⇒ omit (many servers don't send it).
     * @param string|null   $honeytokenKey   HMAC key for the tamper-evident bait cookie. Set it and
     *                                       the app plants a signed `role=user` cookie; a request that
     *                                       returns it altered (e.g. role=admin) is a HIGH-signal
     *                                       privilege-escalation attempt. null ⇒ feature off.
     */
    public function __construct(
        public string $mode = 'detect',
        public ?Closure $gate = null,
        public string $pathScope = 'matched-only',
        public ?Closure $personaSeed = null,
        public string $personaBreadth = 'coherent',
        public string $responseStyle = Style::MINIMAL,
        public string $severityCeiling = 'high',
        public int $maxBodyBytes = 65536,
        public int $latencyMs = 0,
        public int $latencyJitterMs = 0,
        public bool $attackEmulation = false,
        public ?Closure $trustedBypass = null,
        public ?Closure $killSwitch = null,
        public ?Closure $probeSignature = null,
        public string $seedSalt = '',
        public array $exclude = [],
        public bool $nucleiReflection = true,
        public ?string $serverHeader = null,
        public ?string $poweredBy = null,
        public ?string $honeytokenKey = null
    ) {
    }

    public function respondEnabled(): bool
    {
        return $this->mode === 'respond';
    }

    /**
     * Microseconds to pause before serving a fake — a base delay plus RANDOM jitter (not
     * seeded, so re-scans vary) so responses aren't the instant, uniform sub-millisecond
     * replies that fingerprint a honeypot. 0 by default. Under php-fpm keep the worker
     * pool sized for the delay; never large enough to exhaust it.
     */
    public function serveDelayMicros(): int
    {
        $jitter = $this->latencyJitterMs > 0 ? random_int(0, $this->latencyJitterMs) : 0;

        return max(0, ($this->latencyMs + $jitter) * 1000);
    }

    public function killSwitchTripped(): bool
    {
        return $this->killSwitch !== null && ($this->killSwitch)() === true;
    }

    public function isTrusted(RequestContext $r): bool
    {
        return $this->trustedBypass !== null && ($this->trustedBypass)($r) === true;
    }

    public function gateOpen(RequestContext $r): bool
    {
        return $this->gate !== null && ($this->gate)($r) === true;
    }

    /**
     * Root / homepage-class (sig=1) entries fire only when this returns true, so an
     * ordinary visitor to "/" never gets a fake. Defaults closed.
     */
    public function hasProbeSignature(RequestContext $r): bool
    {
        return $this->probeSignature !== null && ($this->probeSignature)($r) === true;
    }

    /**
     * Determinism source for persona selection. Core default is host + salt only:
     * spoof-proof and byte-identical on re-scan. It is deliberately NOT seeded on a
     * client-IP header — an attacker-controlled X-Forwarded-For would let a prober
     * rotate or enumerate personas. Behind a proxy the app should override with a
     * network-coarsened real client IP so distinct sources still spread across personas.
     */
    public function seedFor(RequestContext $r): string
    {
        $base = $this->personaSeed !== null
            ? (string) ($this->personaSeed)($r)
            : $r->host;

        return $base . '|' . $this->seedSalt;
    }
}
