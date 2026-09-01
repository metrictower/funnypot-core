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
     * @param string[]      $exclude         template ids or tags to never SERVE (respond path only;
     *                                        detection is unaffected — see $ignoreTemplates)
     * @param string[]      $ignoreTemplates template ids or tags to never let DRIVE a detection
     *                                        (classify path only; serving is unaffected — see $exclude)
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

    /** @var string[] template ids or tags to never SERVE (respond path); detection is unaffected */
    public $exclude;

    /**
     * @var string[] template ids or tags to exclude from DETECTION (classify path). A request whose
     * matching templates are all in this list carries no evidence and classifies CLEAN; any other
     * matching template still drives the detection (drop-from-evidence). Distinct from $exclude:
     * this governs classification, $exclude governs serving. The engine flips it to a set once for
     * O(1) per-request lookup.
     */
    public $ignoreTemplates;

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

    /**
     * @var bool fail-safe origin posture. false (default) ⇒ treat this install as embedded/inline in
     * a response-owning host, where a decoy that reflects attacker request bytes into an active
     * context (an HTML body or a redirect Location) would be a live XSS/open-redirect in the host's
     * real origin — so such decoys are suppressed from SERVING (detection is unaffected). true ⇒ a
     * standalone isolated-origin honeypot that owns its origin, where reflecting those bytes is safe
     * bait; the reflect/redirect decoys serve intact.
     */
    public $isolatedOrigin;

    /**
     * @var bool opt-in LLM prompt-injection seeding. false (default) ⇒ no injection block is ever
     * appended and served bodies are byte-identical to today's output. true ⇒ decoy rules that carry
     * a `taunt:` carrier also get an INERT, DEFENSIVE-ONLY misdirection block (+ a self-beacon URL when
     * $beaconUrl is set) appended in the file's own comment syntax. Off by default because seeding this
     * technique is itself a deception-tell to hidden-comment scanners (readme_prompt_injection-class) —
     * mirrors the $isolatedOrigin / $nucleiReflection opt-in gating precedent.
     */
    public $promptInjectionSeeding;

    /**
     * @var string|null operator-owned public HTTPS beacon base URL for the prompt-injection self-beacon.
     * A fetch of the seeded URL is the "an autonomous LLM agent, not a plain scanner, processed our
     * content" signal (the app follow-up owns the endpoint + logging). MUST be a normal public host —
     * never loopback/RFC1918/169.254.169.254 (harmful AND refused by hardened agents' fetch_url).
     * null ⇒ no beacon URL is emitted (the misdirection block still appears when seeding is on).
     */
    public $beaconUrl;

    /**
     * @var bool opt-in confirmation-resistant proof mutation (FP-0232). false (default) ⇒ every
     * {{volatile.*}} proof token renders its stable seeded value (delegating to the {{fake.*}} path),
     * so served output is byte-identical to today. true ⇒ armed decoy templates mint a fresh,
     * non-reproducible proof token from CSPRNG entropy per request, defeating the Tier-H
     * reproducible-proof retest gate while persona identity and page structure stay byte-stable. Off by
     * default — the mutation is a deliberate tarpit and a default install never mutates anything;
     * mirrors the $isolatedOrigin / $promptInjectionSeeding opt-in gating precedent.
     */
    public $volatileProof;

    /**
     * @var array<string,bool> per-reflect-class serve override. Keyed by a rule's reflect_class
     * ('xss', 'open-redirect', 'fs-read'). A MISSING key defaults to ENABLED, so a standalone
     * isolatedOrigin=true install reflects every class exactly as it does today. Set a class to
     * false to WITHHOLD that class even from an isolated origin. This map can ONLY subtract: it is
     * AND-ed with isolatedOrigin (see serveReflector()), so it can never re-enable reflection in an
     * embedded host — isolatedOrigin=false ⇒ every class stays suppressed regardless of this map.
     * Fail-safe. A reflects_input rule that carries no reflect_class keys off the sentinel class
     * 'default' (so set reflectClasses['default']=false to disable any untagged reflector). Values
     * are read as booleans; a non-bool is coerced (only false-y disables), never widening the gate.
     */
    public $reflectClasses;

    public function __construct(
        string $mode = 'detect',
        ?Closure $gate = null,
        string $pathScope = 'matched-only',
        ?Closure $personaSeed = null,
        string $personaBreadth = 'coherent',
        string $responseStyle = Style::REALISTIC,
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
        ?string $decoySessionKey = null,
        array $ignoreTemplates = [],
        bool $isolatedOrigin = false,
        bool $promptInjectionSeeding = false,
        ?string $beaconUrl = null,
        bool $volatileProof = false,
        array $reflectClasses = []
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
        $this->ignoreTemplates = $ignoreTemplates;
        $this->isolatedOrigin = $isolatedOrigin;
        $this->promptInjectionSeeding = $promptInjectionSeeding;
        $this->beaconUrl = $beaconUrl;
        $this->volatileProof = $volatileProof;
        $this->reflectClasses = $reflectClasses;
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

    /** Per-class enable flag. Missing key ⇒ enabled (preserves today's isolated-origin behavior). */
    public function reflectClassEnabled(string $class): bool
    {
        return $this->reflectClasses[$class] ?? true;
    }

    /**
     * The single reflection decision. Reflection serves ONLY from an isolated origin AND when the
     * class is not disabled. The isolatedOrigin term is first and dominates: an embedded host
     * (false) never reflects, whatever the class map says — the knob can only ever subtract.
     */
    public function serveReflector(string $class): bool
    {
        return $this->isolatedOrigin && $this->reflectClassEnabled($class);
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
