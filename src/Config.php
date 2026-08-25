<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Closure;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Support\PersonaIdentity;

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
    /** @var string off | detect | respond */
    public $mode;

    /** @var Closure|null fn(RequestContext):bool — app suspicion predicate; null ⇒ closed (false) */
    public $gate;

    /** @var string matched-only (only compiled paths) | any */
    public $pathScope;

    /** @var Closure|null fn(RequestContext):string — determinism source; null ⇒ host + salt */
    public $personaSeed;

    /** @var string coherent (one product persona) | greedy */
    public $personaBreadth;

    /** @var string minimal | realistic | taunt (see Response\Style) */
    public $responseStyle;

    /** @var string refuse to fabricate anything stronger than this */
    public $severityCeiling;

    /** @var int hard cap; a larger synthesized body is refused */
    public $maxBodyBytes;

    /** @var int optional tarpit delay applied by the emitter, never the core */
    public $latencyMs;

    /** @var int random jitter (ms) added to the base delay so replies aren't uniform */
    public $latencyJitterMs;

    /** @var bool interactive attack-class emulation on a route miss */
    public $attackEmulation;

    /** @var Closure|null fn(RequestContext):bool — own scanners; true ⇒ never serve fakes */
    public $trustedBypass;

    /** @var Closure|null fn():bool — true ⇒ respond disabled (un-poison) */
    public $killSwitch;

    /** @var Closure|null fn(RequestContext):bool — root/homepage (sig=1) fires ONLY when true; null ⇒ never */
    public $probeSignature;

    /** @var string per-deploy salt so persona differs per site */
    public $seedSalt;

    /** @var string[] template ids or tags to never serve */
    public $exclude;

    /** @var bool false drops every nuclei-corpus fake (attack and route emulations still serve) */
    public $nucleiReflection;

    /** @var string|null Server banner emitted on every response; null ⇒ don't force one */
    public $serverHeader;

    /** @var string|null X-Powered-By emitted on every response; null ⇒ omit */
    public $poweredBy;

    /** @var string|null HMAC key for the tamper-evident bait cookie; null ⇒ feature off */
    public $honeytokenKey;

    /** @var string|null per-deploy persona-material override; null/'' ⇒ fall back to $seedSalt */
    public $deploySeed;

    /** @var string|null per-deploy secret signing the decoy mock-auth session cookie; null ⇒ feature off */
    public $decoySessionKey;

    public function __construct(
        string $mode = 'detect',
        ?Closure $gate = null,
        string $pathScope = 'matched-only',
        ?Closure $personaSeed = null,
        string $personaBreadth = 'coherent',
        string $responseStyle = Style::MINIMAL,
        string $severityCeiling = 'high',
        int $maxBodyBytes = 65536,
        int $latencyMs = 0,
        int $latencyJitterMs = 0,
        bool $attackEmulation = false,
        ?Closure $trustedBypass = null,
        ?Closure $killSwitch = null,
        ?Closure $probeSignature = null,
        string $seedSalt = '',
        array $exclude = [],
        bool $nucleiReflection = true,
        ?string $serverHeader = null,
        ?string $poweredBy = null,
        ?string $honeytokenKey = null,
        ?string $deploySeed = null,
        ?string $decoySessionKey = null
    ) {
        $this->mode = $mode;
        $this->gate = $gate;
        $this->pathScope = $pathScope;
        $this->personaSeed = $personaSeed;
        $this->personaBreadth = $personaBreadth;
        $this->responseStyle = $responseStyle;
        $this->severityCeiling = $severityCeiling;
        $this->maxBodyBytes = $maxBodyBytes;
        $this->latencyMs = $latencyMs;
        $this->latencyJitterMs = $latencyJitterMs;
        $this->attackEmulation = $attackEmulation;
        $this->trustedBypass = $trustedBypass;
        $this->killSwitch = $killSwitch;
        $this->probeSignature = $probeSignature;
        $this->seedSalt = $seedSalt;
        $this->exclude = $exclude;
        $this->nucleiReflection = $nucleiReflection;
        $this->serverHeader = $serverHeader;
        $this->poweredBy = $poweredBy;
        $this->honeytokenKey = $honeytokenKey;
        $this->deploySeed = $deploySeed;
        $this->decoySessionKey = $decoySessionKey;
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

    /**
     * Per-deploy, cross-request-stable seed (an int) for a single host-wide persona identity.
     * It takes NO RequestContext on purpose: one deploy presents one coherent identity to every
     * caller. Material is an explicit `deploySeed` when set, else the `seedSalt`.
     *
     * Derived through PersonaIdentity::seedFromMaterial — the SAME canonical function the app tier
     * feeds its persona material — so when both tiers are given the same material they resolve the
     * identical PersonaIdentity, and a scanner sees ONE company across templated and LLM paths. It is
     * a 60-bit sha256 digest of a PRIVATE, operator-set material (never the public cert CN), so a
     * crafted request cannot target it; and the persona identity is taken from this injected seed
     * regardless of the per-request render seed, so an incidental collision with it is harmless.
     */
    public function deploySeed(): int
    {
        $m = ($this->deploySeed !== null && $this->deploySeed !== '') ? $this->deploySeed : $this->seedSalt;

        return PersonaIdentity::seedFromMaterial($m);
    }
}
