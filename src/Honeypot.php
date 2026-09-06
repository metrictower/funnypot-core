<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Contracts\CompiledStore;
use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\Reaction\ParamReactionDecorator;
use Funnypot\Core\Reaction\QueryIntentClassifier;
use Funnypot\Core\Response\EmulatorRegistry;
use Funnypot\Core\Rules\ServedStringWalker;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PathNormalizer;
use Funnypot\Core\Support\PersonaSelector;
use Funnypot\Core\Support\Severity;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\Template\TemplateAttackEmulator;

/**
 * Core engine. Framework-agnostic and side-effect-free (all logging/scoring/banning
 * happen in the host app's Observer).
 *
 * detect() is always safe to call — it routes an incoming request to the template(s)
 * it probes for and returns a signal. respond() honours Config: it only serves a fake
 * when the app has opted into respond mode and every safety gate passes.
 */
final class Honeypot implements Engine
{
    /** @var CompiledStore */
    private $store;

    /** @var Config */
    private $config;

    /** @var Observer */
    private $observer;

    /** @var ResponseSynthesizer */
    private $synthesizer;

    /** @var ParamReactionDecorator */
    private $reactions;

    /** @var TemplateAttackEmulator|null */
    private $attackEmulator;

    /** @var string[] template ids/pids/tags never served: Config->exclude merged with the disabled catalog set */
    private $effectiveExclude;

    /** @var array<string,int> Config->ignoreTemplates flipped to a set: ids/tags never allowed to drive a detection */
    private $ignoreTemplates;

    /** @var bool */
    private $nucleiEnabled;

    /** @var FingerprintGuard|null runtime egress guard, loaded once (null ⇒ could not load ⇒ fail closed) */
    private $runtimeGuard;

    /** @var bool whether the runtime guard load has been attempted */
    private $runtimeGuardLoaded = false;

    /** @var array<string,bool> per-rule-id cache of ServedStringWalker::reflectsCaptures() */
    private $reflectorCache = [];

    /** @var int the deploy identity seed, snapshotted once at construction (never re-read per request) */
    private $deploySeed;

    public function __construct(
        CompiledStore $store,
        ?Config $config = null,
        ?Observer $observer = null
    ) {
        $this->store = $store;
        $this->config = $config ?? new Config();
        $this->observer = $observer ?? new NullObserver();

        // One per-deploy identity seed drives {{persona.*}} in both runtime renderers below, so the
        // template tier and the app LLM tier present one coherent site identity. Fabricated {{fake.*}}
        // secrets stay per-request (per-attacker) — only the identity is deploy-stable. Snapshotted
        // once here (not re-read per request): mint/gate and the retrieval probe must derive the same
        // decoy-session payload, so mutating Config after construction cannot split their identity.
        $this->deploySeed = $this->config->deploySeed();
        $personaSeed = $this->deploySeed;

        // FP-0276 boot-time seed-health signal. NON-SERVED and material-only (never re-derives, never
        // touches $personaSeed's value). Fired once at construction; an Observer that also implements
        // HealthObserver receives it, swallowed per FP-0252 so a throwing observer cannot break
        // construction or change served bytes. The pull API Honeypot::seedHealth() is the primary path.
        if ($this->observer instanceof HealthObserver) {
            try {
                $this->observer->onSeedHealth($this->config->seedHealth());
            } catch (\Throwable $e) {
                // Swallow: a health observer is a diagnostic seam, never a serving dependency.
            }
        }

        // FP-0239: opt-in prompt-injection seeding. Read the gate + build the per-deploy self-beacon
        // canary off Config, then hand both DISCRETE values down the real render path
        // (EmulatorRegistry::default → RouteTemplateEmulator). No SynthesisConfig — it is dead on this
        // path. The beacon canary is built only when the gate is on AND a beacon URL + a signing key
        // are configured; the URL carries a server-signed token (Honeytoken::beaconToken, same HMAC as
        // the bait cookie — no new crypto), never any attacker input.
        $beaconCanary = [];
        // `?:` not `??` (FP-0244): an operator who sets decoySessionKey to '' means "no dedicated
        // beacon key", so it must fall through to honeytokenKey — `??` only skips null and would sign
        // the beacon with an empty key. `?:` treats '' (and null) as absent; the guard below still
        // rejects a null/empty result, so a truly unset key fails closed (no beacon).
        $beaconKey = ($this->config->decoySessionKey ?? '') !== '' ? $this->config->decoySessionKey : $this->config->honeytokenKey;
        if (
            $this->config->promptInjectionSeeding
            && $this->config->beaconUrl !== null && $this->config->beaconUrl !== ''
            && $beaconKey !== null && $beaconKey !== ''
            // FP-0244 defense-in-depth: a misconfigured beacon URL pointed at a private/reserved/
            // loopback host or the cloud metadata endpoint is an operator footgun (a seeded agent GET
            // could probe the operator's own internal network). It is operator-owned config, outside
            // the attacker threat model, but this cheap guard fails CLOSED — no beacon — on rejection.
            && self::beaconUrlIsSafe($this->config->beaconUrl)
        ) {
            $token = (new Honeytoken($beaconKey))->beaconToken((string) $personaSeed);
            $sep = strpos($this->config->beaconUrl, '?') === false ? '?' : '&';
            $beaconCanary['beacon'] = $this->config->beaconUrl . $sep . 't=' . $token;
        }

        $this->synthesizer = new ResponseSynthesizer(
            EmulatorRegistry::default($personaSeed, $this->config->promptInjectionSeeding, $beaconCanary, $this->config->volatileProof),
            $this->config->responseStyle,
            $this->config->serverHeader,
            $this->config->poweredBy,
            $personaSeed
        );

        // FP-0157 param reactions: an opt-in, isolated-origin-only decorator that appends an inert
        // query reaction to an already-synthesized decoy route. Built here (next to the synthesizer)
        // so its fingerprint guard loads once per engine, never per request. Dormant unless
        // Config::$paramReactivity AND serveReflector('param-reaction', request) both hold.
        $this->reactions = new ParamReactionDecorator($this->config, $personaSeed);

        // What we will not serve is driven by primitives on Config: the exclude deny-set (template
        // ids / pids / tags) and the nuclei-corpus group flag. An operator UI (the app's emulation
        // catalog) resolves its toggles into these before constructing the engine; the engine stays
        // free of any catalog dependency. A disabled attack id in the exclude set is also skipped.
        $this->effectiveExclude = $this->config->exclude;
        $this->nucleiEnabled = $this->config->nucleiReflection;

        // Detection-side deny-set, distinct from $effectiveExclude (serving). Flipped once here so
        // the per-request membership test in applyIgnore() is O(1).
        $this->ignoreTemplates = array_flip($this->config->ignoreTemplates);

        $this->attackEmulator = $this->config->attackEmulation
            ? TemplateAttackEmulator::fromPackage([], $personaSeed, $this->config->decoySessionKey, $this->config->volatileProof, $this->config->promptInjectionSeeding)->disable($this->config->exclude)
            : null;
    }

    /**
     * The deploy's NON-SERVED seed-health report (FP-0276) — the pull companion of the HealthObserver
     * push. An app status page / dashboard reads this to surface an unseeded or fleet-constant install
     * (identity material empty/placeholder, or an empty render salt) without configuring an observer.
     * Material-only, never re-derives; delegates to Config::seedHealth() so pull and push return the
     * identical array. Added on the final class only — the Engine/Evaluator interfaces are not extended
     * (an interface addition would break every app implementer).
     *
     * @return array{identity:string,render_salt:string,ok:bool,warnings:list<string>}
     */
    public function seedHealth(): array
    {
        return $this->config->seedHealth();
    }

    /**
     * FP-0244 — defense-in-depth validation of the operator-configured self-beacon URL. True only when
     * the URL is a syntactically valid http(s) URL whose host is NOT a loopback/private/reserved IP,
     * the cloud metadata endpoint (169.254.169.254 / fd00:ec2::254), or an obviously-internal name.
     * A rejected URL disables the beacon (fail closed). This is not a full SSRF defence (a public name
     * can still resolve to a private A record) — it is a cheap footgun guard for the common misconfig.
     */
    private static function beaconUrlIsSafe(string $url): bool
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($url);
        if ($parts === false) {
            return false;
        }
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        if ($scheme !== 'http' && $scheme !== 'https') {
            return false;
        }
        // strip IPv6 literal brackets, then the FQDN-root trailing dot (a trailing dot is a valid,
        // resolvable host form; without this it would defeat the metadata-name and internal-suffix
        // checks below — flagged by both FP-0244 reviewers).
        $host = rtrim(strtolower(trim((string) ($parts['host'] ?? ''), '[]')), '.');
        if ($host === '') {
            return false;
        }
        // Explicit metadata / loopback hostnames (169.254.169.254 is also caught by NO_RES_RANGE below,
        // but name it here per the ticket so intent is unmistakable).
        if (in_array($host, [
            'localhost', 'ip6-localhost', 'metadata', 'metadata.google.internal',
            '169.254.169.254', 'fd00:ec2::254',
        ], true)) {
            return false;
        }
        // A literal IP must be a public, non-reserved, non-private address.
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
        }
        // A DNS name ending in an internal-only suffix, or a dotless single-label host, is rejected as
        // internal. A normal public FQDN passes (its runtime resolution is outside this static guard).
        if (preg_match('/(^|\.)(internal|intranet|local|localhost|lan|home|corp)$/', $host) === 1) {
            return false;
        }

        return strpos($host, '.') !== false;
    }

    /**
     * Build against the artifact bundled with the package. Pass a Config to enable
     * respond mode; the default is inert (detect only).
     */
    public static function default(?Config $config = null, ?Observer $observer = null): self
    {
        return new self(PhpArrayStore::fromPackage(), $config, $observer);
    }

    /**
     * Back-compat detection shim: detect() is classify() against an empty SiteProfile, projected
     * to its Detection. No caller breaks (two-phase design §2.1).
     */
    public function detect(RequestContext $r): Detection
    {
        return $this->classify($r, SiteProfile::empty())->detection;
    }

    /**
     * Content detection only (two-phase design §2.1): route resolution, then — on a miss — the
     * attack-payload matcher, consulting the SiteProfile real-route oracle. Always safe to call:
     * no gates, no I/O, no side effects. Answers "what is this request, as content?" — never
     * "should we act?". The request-shape bot signals ride on the Verdict (Phase 1b).
     *
     * A thin decorator over classifyContent(): the content verdict is produced first (byte-identical
     * to the pre-OOB classifier), then every registered signal-only probe in the OobSignalRegistry
     * (OAST/SSRF collaborator zones, Log4Shell/JNDI) folds one high-signal, SIGNAL-ONLY match in via
     * foldOob(). Detect-only: the registry is pure string matching (no DNS, no fetch) and the fold
     * never touches fakeHandle, so no callback is ever made and no served byte changes.
     */
    public function classify(RequestContext $r, SiteProfile $profile): Verdict
    {
        $verdict = $this->classifyContent($r, $profile);

        // OOB signal-probe registry (FP-0256): every registered signal-only probe (OAST/SSRF
        // collaborator zones, Log4Shell/JNDI) is pure string matching — no DNS, no fetch — and
        // each hit folds one high-signal, SIGNAL-ONLY match via foldOob(). The fold never touches
        // fakeHandle, so no served byte changes and no callback is ever made.
        foreach (OobSignalRegistry::matches($r) as $match) {
            $verdict = $this->foldOob($verdict, $match);
        }

        // Honeytoken-retrieval fold (delegates to foldOob, like the registry probes): iff a decoy-session key is
        // configured AND the request presents a valid minted authenticated cookie, the attacker walked the
        // mock-auth trap and is pulling loot — fold one high-signal, SIGNAL-ONLY match. An unset key
        // makes this a no-op, so a build that never enabled the decoy session is byte- and
        // signal-identical to before this seam existed.
        $decoyKey = (string) ($this->config->decoySessionKey ?? '');
        if ($decoyKey !== '' && DecoySessionProbe::authenticated($r, $decoyKey, $this->deploySeed)) {
            $verdict = $this->foldHoneytoken($verdict);
        }

        return $verdict;
    }

    /**
     * The content classifier proper — the pre-OAST body of classify(), moved verbatim (no logic
     * change). classify() is the public seam and folds the OAST signal on top of this; every return
     * path below is unchanged.
     */
    private function classifyContent(RequestContext $r, SiteProfile $profile): Verdict
    {
        $signals = $this->botSignals($r);
        $anomaly = $signals->weight;

        $resolved = $this->resolveEntry($r->method, $r->path);
        if ($resolved !== null) {
            [$key, $entry] = $resolved;
            $bundles = $entry['b'] ?? [];

            // An entry with no servable bundles, or a path the host declares as a genuine route,
            // is not a probe — never shadow a live endpoint (M2). Mirrors respond()'s early null.
            if ($bundles === [] || $profile->hasRoute($r->method, PathNormalizer::normalize($r->path))) {
                return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
            }

            // Path-override (WP-Phase-2): a request-aware rule may claim this path via owns_path and
            // override the static exact-store stub. Sits AFTER the M2 guard (so a live host route is
            // never shadowed) and BEFORE the route verdict; on a decline it falls through to the
            // static bundle below — zero coverage loss, no new throw path.
            if ($this->attackEmulator !== null && $this->attackEmulator->ownsPath($r->path)) {
                $ov = $this->attackEmulator->matchRule($r);
                // A persona-gated rule (e.g. the Next.js RSC responder) fires ONLY where the served
                // `/` persona is the gate's pid — personaGateAllows() reproduces the serve-path pick
                // byte-for-byte, so gate-open ⟺ this deploy actually presents that stack. A closed
                // gate is treated as a decline (fall through below), never a fleet-wide override.
                if ($ov !== null && $this->personaGateAllows($ov['rule'], $r)) {
                    $rule = $ov['rule'];
                    $detection = TemplateAttackEmulator::detectionForRule($rule);
                    $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $ov['captures']);

                    return new Verdict(
                        Verdict::ATTACK_CLASS,
                        $detection,
                        $detection->highestSeverity,
                        $anomaly,
                        $signals,
                        $handle
                    );
                }

                // Owned path, but the request-aware rule declined (a rare path/method variant the
                // rule's stricter match missed, or a closed persona gate). The static store bundle at
                // an owned login path may be the exact login-SUCCESS decoy owns_path exists to shadow
                // — never re-expose an authenticated success on a decline. Degrade to CLEAN when the
                // fallthrough entry carries an auth-success witness. A ROOT/homepage entry (all sig=1)
                // is by definition an ordinary-visitor path, never a login-success decoy, so it is
                // exempt: it must fall through to the persona lottery below (a gated owns_path rule
                // that claims `/`, like the RSC responder, would otherwise 404 the homepage on every
                // deploy whose `/` set happens to carry a session-cookie persona). A benign non-root
                // entry (a login page, no witness) still falls through to the static route verdict.
                if (!$this->isRootEntry($bundles) && $this->hasAuthSuccessWitness($bundles)) {
                    return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
                }
            }

            $detection = $this->detectionFor($key, $this->detectIds($entry));

            // Ignore-from-detection (Config->ignoreTemplates): when the host has silenced every
            // template that would have matched here, the entry carries no evidence and is no longer
            // a probe — classify CLEAN. Drop-from-evidence: an entry with any surviving match still
            // classifies below. Guarded on the set so behaviour is untouched when the feature is off.
            if ($this->ignoreTemplates !== [] && $detection->isEmpty()) {
                return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
            }

            $handle = FakeHandle::route($key, $this->paramIntentFor($r, $bundles));

            // A bare root/homepage entry (all bundles sig=1) is an ordinary-visitor path only under
            // GET/HEAD: classify clean natively (the probe-signature predicate is a policy input,
            // not content). An ambient entry (all bundles amb=1) is a path fetched unprompted, again
            // only under GET/HEAD — a corpus match there is not itself evidence, so it classifies
            // AMBIENT rather than a probe. Any other verb, or any non-root/non-ambient entry, is a
            // scanner probe. The handle rides through in every case so the policy can still
            // synthesize when it supplies a signature.
            $classification = $this->homepageSafe($r->method, $bundles)
                ? Verdict::CLEAN
                : ($this->ambientSafe($r->method, $bundles) ? Verdict::AMBIENT : Verdict::SCANNER_PROBE);

            return new Verdict($classification, $detection, $detection->highestSeverity, $anomaly, $signals, $handle);
        }

        // Bounded HTTP method coverage (FP-0011). Only after an exact-route miss, and only for the
        // three method-discovery verbs this responder implements, does a servable compiled path get
        // a coherent OPTIONS/TRACE/PROPFIND answer instead of a blind 404. An exact authored method
        // route (e.g. the shipped TRACE / or OPTIONS /wp-json/omapp/v1/support lures) already won at
        // resolveEntry above, so this never shadows one; on a decline it falls through to the
        // parameter/attack scan below, exactly as an uncovered miss does today.
        $method = strtoupper($r->method);
        if ($method === 'OPTIONS' || $method === 'TRACE' || $method === 'PROPFIND') {
            $coverage = $this->methodCoverageVerdict($r, $method, $anomaly, $signals, $profile);
            if ($coverage !== null) {
                return $coverage;
            }
        }

        if ($this->attackEmulator !== null) {
            // Param-route tier: a parameterized path the exact store can't key, dispatched by
            // prefix bucket. It sits BETWEEN the exact-store miss and the linear attack scan, and
            // a hit returns here — so a matched param route skips the attack gauntlet entirely. The
            // served entry is attack-rule shaped, so it rides the same ATTACK_CLASS handle + render.
            $pm = $this->attackEmulator->matchParamRoute($r);
            if ($pm !== null) {
                $rule = $pm['rule'];
                $detection = TemplateAttackEmulator::detectionForRule($rule);
                $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $pm['captures']);

                return new Verdict(
                    Verdict::ATTACK_CLASS,
                    $detection,
                    $detection->highestSeverity,
                    $anomaly,
                    $signals,
                    $handle
                );
            }

            $matched = $this->attackEmulator->matchRule($r);
            // A persona-gated rule reached on a store MISS (the linear scan) is gated the same way as
            // on the owns_path override path, so a future gated rule on a store-miss path can't bypass
            // the gate via this branch. A closed gate falls through to the CLEAN verdict below (the app
            // serves its own 404). Ungated rules hit the isset() early-out in personaGateAllows() and
            // are unaffected — behaviour for every existing rule is byte-identical.
            if ($matched !== null && $this->personaGateAllows($matched['rule'], $r)) {
                $rule = $matched['rule'];
                $detection = TemplateAttackEmulator::detectionForRule($rule);
                $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $matched['captures']);

                return new Verdict(
                    Verdict::ATTACK_CLASS,
                    $detection,
                    $detection->highestSeverity,
                    $anomaly,
                    $signals,
                    $handle
                );
            }
        }

        return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
    }

    /**
     * Fold one OOB signal-probe match (from OobSignalRegistry) into a content Verdict as a
     * high-signal, SIGNAL-ONLY match. The generalization of the old foldOast (FP-0256): the match
     * is now built by the registry and passed in, and the severity ceiling uses the match's own
     * severity (so a critical log4shell hit raises the ceiling to critical) — for a 'high' OAST
     * match this is arithmetic-identical to the pre-FP-0256 foldOast. Decorator invariants (all
     * falsifiable in OastSeamTest / Log4ShellSeamTest):
     *  - NEVER touches fakeHandle: a signal-only CLEAN request keeps fakeHandle === null, so respond()
     *    serves nothing at its early guard — no serve, therefore nothing that could be a callback. A
     *    routed/attack request keeps its existing handle, so its served bytes are unchanged.
     *  - Bumps CLEAN -> SCANNER_PROBE only when fakeHandle === null (the pure signal-only case), and
     *    ALWAYS bumps AMBIENT -> SCANNER_PROBE (the stamp says the PATH is unprompted; an OOB /
     *    honeytoken witness is request-level proof THIS fetch was not — the handle is left in place).
     *    A CLEAN-with-route-handle root entry stays CLEAN so its serve-gating is untouched;
     *    SCANNER_PROBE / ATTACK_CLASS are left as-is (never downgrades an attack coincidence).
     *  - Adds no I/O. The synthetic match lives only inside the Detection (a logging/telemetry
     *    projection); it is never written into a served body or header, so the served response is
     *    byte-identical whether or not the probe fires. NOTE (accuracy): the folded Detection is not
     *    ONLY telemetry — respond() hands it to the app's serve veto, Observer::shouldRespond($r,
     *    $verdict->detection) (the safeShouldRespond call ~line 919), so an app veto keyed on
     *    severity/tags CAN flip VETOED<->SERVED after a retag (e.g. FP-0257's cloud-metadata ->
     *    cloud-metadata-ssrf/critical). CORE serve gating never reads $verdict->severity, so core
     *    bytes are unchanged; the exposure is app-policy-visible, same class as the retag itself.
     */
    private function foldOob(Verdict $v, TemplateMatch $match): Verdict
    {
        $matches = array_merge($v->detection->matches, [$match]);
        $ceiling = Detection::ceilingSeverity($v->detection->highestSeverity ?: 'unknown', $match->severity);
        $detection = new Detection(true, $matches, $v->detection->clusterKey, $ceiling);

        // A signal-only CLEAN miss (null handle) is bumped to SCANNER_PROBE, and an AMBIENT entry
        // is always bumped: the stamp says the PATH is fetched unprompted, but an OOB/honeytoken
        // witness is request-level proof this request was not. CLEAN-with-handle stays CLEAN (its
        // serve-gating must not flip); SCANNER_PROBE / ATTACK_CLASS are never downgraded.
        $classification = $v->classification;
        if (($classification === Verdict::CLEAN && $v->fakeHandle === null) || $classification === Verdict::AMBIENT) {
            $classification = Verdict::SCANNER_PROBE;
        }

        return new Verdict($classification, $detection, $ceiling, $v->anomaly, $v->signals, $v->fakeHandle);
    }

    /**
     * Fold a decoy-session honeytoken RETRIEVAL into a content Verdict as a high-signal, SIGNAL-ONLY
     * match — the attacker presented a minted authenticated cookie and walked the mock-auth breached-DB trap.
     * Delegates to foldOob() with its own TemplateMatch, so it carries the same decorator invariants
     * (all falsifiable in HoneytokenRetrievalSeamTest):
     *  - NEVER touches fakeHandle: the gate still renders the authed body via emulate() unchanged, so
     *    the served bytes are byte-identical whether or not this fires. The synthetic match lives only
     *    inside the Detection (a logging/telemetry projection), never in a served body or header.
     *  - Bumps CLEAN -> SCANNER_PROBE only when fakeHandle === null (a decoy-cookie request that
     *    resolved to no route handle); a CLEAN-with-route-handle verdict keeps its serve-gating, and
     *    SCANNER_PROBE / ATTACK_CLASS are left as-is (never downgrades an attack coincidence).
     *  - Adds no I/O (DecoySessionProbe is pure string work over the Cookie header).
     *
     * Kept as a named private method (not inlined into classify()) so its config-gated call site and
     * the HoneytokenRetrievalSeamTest source-slice anchor stay put; it is deliberately OUTSIDE the
     * static OobSignalRegistry because DecoySessionProbe is config-dependent (needs decoySessionKey).
     */
    private function foldHoneytoken(Verdict $v): Verdict
    {
        $match = new TemplateMatch(
            'honeytoken-retrieval',
            'high',
            ['honeytoken-retrieval', 'decoy-session', 'breached-db', 'high-confidence'],
            'decoy mock-auth breached-DB retrieval'
        );

        return $this->foldOob($v, $match);
    }

    /**
     * True when every servable bundle for an entry is a root/homepage class (sig=1).
     *
     * INVARIANT (load-bearing for the witness exemption above): sig=1 means "ordinary-visitor entry,
     * never a login-success decoy". The exemption trusts that equivalence to skip the auth-success
     * suppression at `/`, so a login-SUCCESS page (one carrying a Set-Cookie/session witness) must
     * NEVER be authored as sig=1 — do that and it would be silently exempted from the suppression and
     * re-exposed on a decline. Success decoys are sig=0 (attacker-reached), keeping this safe.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function isRootEntry(array $bundles): bool
    {
        foreach ($bundles as $bundle) {
            if ((int) ($bundle['sig'] ?? 0) !== 1) {
                return false;
            }
        }

        return $bundles !== [];
    }

    /**
     * True when every servable bundle for an entry is stamped ambient (amb=1): a path browsers,
     * crawlers and platforms fetch unprompted, so a corpus match here is not itself evidence.
     * ALL-semantics like isRootEntry(): the corpus half and the fold half are rebuilt by different
     * commands (composer build-corpus vs composer build), so a key whose bundles disagree on amb is
     * a stale build — classify it SCANNER_PROBE (the over-reporting direction) rather than suppress
     * a real probe.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function isAmbientEntry(array $bundles): bool
    {
        foreach ($bundles as $bundle) {
            if ((int) ($bundle['amb'] ?? 0) !== 1) {
                return false;
            }
        }

        return $bundles !== [];
    }

    /**
     * Homepage-safe classification predicate (FP-0011): a root/homepage entry (all bundles sig=1) is
     * an ordinary-visitor navigation only under GET or HEAD. Every other verb at a root route
     * (POST/PUT/DELETE/OPTIONS/TRACE/PROPFIND/PURGE) is method discovery, not navigation, so it must
     * keep its scanner-probe classification and reachable handle — this is what makes the authored
     * TRACE / lure serve under the standalone open gate rather than being declined as an ordinary
     * visitor. Used ONLY by classifyContent's root-CLEAN branch; the owns_path decline exemption
     * deliberately keeps the method-blind isRootEntry(), so a gated owns_path rule on `/` is not
     * newly subjected to the auth-success-witness degrade for a non-GET verb.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function homepageSafe(string $method, array $bundles): bool
    {
        $upper = strtoupper($method);
        if ($upper !== 'GET' && $upper !== 'HEAD') {
            return false;
        }

        return $this->isRootEntry($bundles);
    }

    /**
     * Ambient-safe classification predicate (FP-0087): an ambient entry (all bundles amb=1) is an
     * unprompted fetch only under GET or HEAD. A browser/crawler/platform never POSTs a favicon or
     * robots.txt, so any other verb at an ambient path is method discovery, not an unprompted fetch,
     * and keeps its scanner-probe classification. Mirrors homepageSafe() so ambient scoping matches
     * root scoping, and stays the over-reporting direction — a non-GET/HEAD ambient hit is never
     * suppressed as AMBIENT.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function ambientSafe(string $method, array $bundles): bool
    {
        $upper = strtoupper($method);
        if ($upper !== 'GET' && $upper !== 'HEAD') {
            return false;
        }

        return $this->isAmbientEntry($bundles);
    }

    /**
     * The query reaction intent to attach to a resolved decoy route handle (FP-0157), or null. Null
     * unless ALL hold: the reflecting-decoy gate is open for this request (paramReactivity AND
     * serveReflector('param-reaction', $r) — so an embedded origin never attaches an intent); the entry
     * is not a root/homepage entry (an ordinary-visitor path is governed by the probe-signature policy,
     * never a reaction); and the raw query classifies to a bounded intent. The intent never changes the
     * route key, detection, severity, classification, anomaly or signals — a null intent leaves the
     * handle byte-identical to today. The synthesize-time decorator re-gates on the same terms, so a
     * config change or a null-request port between phases still yields the exact base response.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function paramIntentFor(RequestContext $r, array $bundles): ?ParamIntent
    {
        if (!$this->config->paramReactivity
            || !$this->config->serveReflector(ParamReactionDecorator::REFLECT_CLASS, $r)) {
            return null;
        }
        if ($this->isRootEntry($bundles) || $r->query === '') {
            return null;
        }

        return QueryIntentClassifier::classify($r->query);
    }

    /**
     * True when any candidate bundle's header-watch declares an authenticated-session witness
     * (a Set-Cookie / logged-in / session-id marker) — i.e. the bundle is a login-SUCCESS decoy.
     * Used to refuse re-exposing such a bundle on an owns_path override decline.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function hasAuthSuccessWitness(array $bundles): bool
    {
        foreach ($bundles as $bundle) {
            foreach ((array) ($bundle['hw'] ?? []) as $w) {
                $lw = strtolower((string) $w);
                if (strpos($lw, 'set-cookie') !== false
                    || strpos($lw, 'logged_in') !== false
                    || strpos($lw, 'sid=') !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The persona gate for a request-aware owns_path rule that presents a specific stack (the
     * Next.js RSC responder, FP-0229). An UNGATED rule (no `persona_gate`) is always allowed — the
     * isset() early-out keeps every existing rule byte-identical and pays only an array-key check.
     *
     * A gated rule fires ONLY where the deploy's served `/` persona IS the gate's pid. The gate
     * REPRODUCES the serve-path pick exactly: it resolves the homepage entry, filters to servable
     * candidates with the SAME candidates() the serve path uses (buildRouteFake, so any exclude /
     * severityCeiling / nucleiReflection:false is honoured identically), and picks with the SAME
     * seedFor($r). Because seedFor is host+salt only — never path or query — the RSC request
     * (`GET /?_rsc=1`) yields the same seed as that attacker's homepage `GET /`, so the gate's pick
     * is byte-for-byte the persona that attacker is served at `/`. Therefore
     * gate-open ⟺ served-`/`-persona-is-<pid>, by construction, under any config — no raw-vs-filtered
     * divergence, no fleet-wide leak. Fail-closed on a missing entry / empty candidate set (never a
     * throw): a rule that cannot prove its stack is present simply declines.
     *
     * @param array<string,mixed> $rule
     */
    private function personaGateAllows(array $rule, RequestContext $r): bool
    {
        if (!isset($rule['persona_gate'])) {
            return true;
        }

        $resolved = $this->resolveEntry('GET', '/');
        if ($resolved === null) {
            return false;
        }

        $candidates = $this->candidates($resolved[1]['b'] ?? []);
        if ($candidates === []) {
            return false;
        }

        $picked = PersonaSelector::pick($candidates, $this->config->seedFor($r));

        return $picked !== null && ($picked['pid'] ?? null) === $rule['persona_gate'];
    }

    /**
     * Request-shape bot signals (decision S / design §2.4): header-presence, fetch-metadata /
     * client-hint absence, self-consistency contradictions, and a digit-stripped structural
     * header fingerprint. Cheap, position-blind, no I/O. Each fires a flag and adds a small
     * weight; the composite "is this a bot?" call is the policy's, never core's. No version-age
     * detection — the digit-stripping tolerates old-but-legit clients.
     *
     * INPUT-side only: nothing computed here is ever emitted in a response (invariant #1).
     */
    /**
     * Whether the request looks like a top-level navigation rather than a subresource or API call.
     *
     * Reads the VALUE of sec-fetch-mode, not merely its presence. Defaults to true: an unknown
     * request shape is scored as a navigation, so nothing is suppressed without positive evidence.
     *
     * A scanner can of course claim `sec-fetch-mode: cors`. What that buys is **5 points** — the
     * Accept-Language absence, and nothing else. It cannot touch the scanner-UA, empty-UA,
     * client-hint contradiction, platform-mismatch or h2 signals.
     *
     * That bound is not free, it is enforced by two things: `$hasFetchMeta` requires the sec-fetch
     * TRIO, so a lone forged header cannot disarm the client-hint contradiction; and the mode is
     * whitelisted, so an unrecognised value scores as a navigation. An earlier version had neither,
     * and one forged header took a Chrome-UA scanner from 34 to 7.
     *
     * @param array<string,string> $h lowercased headers
     */
    private function isNavigation(array $h): bool
    {
        // Whitelist, never blacklist. sec-fetch-mode is a closed set, so an unrecognised value is
        // itself odd — treating "anything but navigate" as a subresource handed the full suppression
        // to `Sec-Fetch-Mode: banana`, which is the opposite of requiring positive evidence.
        $mode = isset($h['sec-fetch-mode']) ? strtolower(trim($h['sec-fetch-mode'])) : '';
        if ($mode !== '') {
            return !in_array($mode, array('cors', 'no-cors', 'same-origin', 'websocket'), true);
        }

        // Pre-fetch-metadata browsers and libraries: the classic AJAX marker.
        if (isset($h['x-requested-with'])
            && strtolower(trim($h['x-requested-with'])) === 'xmlhttprequest') {
            return false;
        }

        // An Accept asking only for a data format is not a page load.
        if (isset($h['accept'])) {
            $accept = strtolower(trim($h['accept']));
            if ($accept !== '' && strpos($accept, 'text/html') === false
                && strpos($accept, 'application/xhtml') === false
                && (strpos($accept, 'application/json') === 0 || strpos($accept, 'text/event-stream') === 0)) {
                return false;
            }
        }

        return true;
    }

    private function botSignals(RequestContext $r): BotSignalSet
    {
        $h = $this->lowercaseHeaders($r->headers);
        $ua = isset($h['user-agent']) ? trim($h['user-agent']) : '';
        $uaClass = $this->classifyUserAgent($ua);

        $flags = [];
        $weight = 0;

        // Is this a top-level navigation, or a subresource/API call the page made?
        //
        // Browsers send a different header set for each. Accept-Language and a document-shaped
        // Accept belong to a navigation; on fetch/XHR Chrome omits the former and sends `*/*` for
        // the latter. Scoring their absence unconditionally charged every AJAX call on a JS-heavy
        // site — measured at anomaly 5 for a plain XHR and 17 for a bare fetch(), from the same
        // browser that scored 0 on the navigation a moment earlier.
        //
        // Suppressed, not merely re-weighted: on a non-navigation these headers are irrelevant
        // rather than weak evidence, and a smaller weight still accumulates across a page's worth
        // of requests.
        $navigation = $this->isNavigation($h);

        // Header presence — the coarsest signal.
        if (!isset($h['accept'])) {
            $flags[BotSignalSet::MISSING_ACCEPT] = true;
            $weight += 5;
        }
        if ($navigation && !isset($h['accept-language'])) {
            $flags[BotSignalSet::MISSING_ACCEPT_LANGUAGE] = true;
            $weight += 5;
        }
        // NOT suppressed on a subresource: Accept-Encoding is a forbidden header name, so the
        // browser sets it on fetch/XHR exactly as on a navigation. Unlike Accept-Language it is
        // never legitimately absent, and the XHR false positive this change fixed was 5 points of
        // Accept-Language alone.
        if (!isset($h['accept-encoding'])) {
            $flags[BotSignalSet::MISSING_ACCEPT_ENCODING] = true;
            $weight += 5;
        }
        if ($ua === '') {
            $flags[BotSignalSet::EMPTY_USER_AGENT] = true;
            $weight += 10;
        }
        if ($uaClass === BotSignalSet::UA_SCANNER) {
            $flags[BotSignalSet::SCANNER_USER_AGENT] = true;
            $weight += 20;
        }

        $claimsBrowser = stripos($ua, 'mozilla') !== false;
        $claimsChromium = preg_match('/chrome|chromium|crios|edg\//i', $ua) === 1;
        // The TRIO, not any one header. A real browser sends sec-fetch-site, -mode and -dest
        // together on both navigations and subresources (only -user is navigation-only). Accepting
        // any single header let one forged `Sec-Fetch-Mode: cors` disarm the 15-point client-hint
        // contradiction below — measured, that took a Chrome-UA scanner from 34 to 7.
        $hasFetchMeta = isset($h['sec-fetch-site']) && isset($h['sec-fetch-mode'])
            && isset($h['sec-fetch-dest']);
        $hasClientHints = isset($h['sec-ch-ua']) || isset($h['sec-ch-ua-mobile'])
            || isset($h['sec-ch-ua-platform']);

        // Fetch-metadata / client-hint absence — low weight alone; leans on the pairing below.
        if (!$hasFetchMeta) {
            $flags[BotSignalSet::MISSING_FETCH_METADATA] = true;
            $weight += 2;
        }
        if (!$hasClientHints) {
            $flags[BotSignalSet::MISSING_CLIENT_HINTS] = true;
            $weight += 2;
        }

        // Self-consistency contradictions — a contradiction beats an absence.
        // No UA class is exempt. A crawler claim is an unverified string anyone can send, so
        // exempting it here would sell this signal for the price of one appended word. Forgiving a
        // real crawler is the host's call, after the reverse-DNS check core cannot perform.
        if ($claimsChromium && !$hasClientHints && !$hasFetchMeta) {
            $flags[BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS] = true;
            $weight += 15;
        }
        // `*/*` is what fetch() sends by default, so it is normal for a subresource and odd only
        // for a navigation.
        if ($navigation && $claimsBrowser && isset($h['accept']) && trim($h['accept']) === '*/*') {
            $flags[BotSignalSet::ACCEPT_WILDCARD_FROM_BROWSER] = true;
            $weight += 10;
        }
        if ($this->isHttp2($r->httpVersion) && isset($h['connection'])) {
            $flags[BotSignalSet::H2_FORBIDDEN_CONNECTION] = true;
            $weight += 15;
        }
        if (isset($h['accept-encoding']) && stripos($h['accept-encoding'], 'gzip') === false) {
            $flags[BotSignalSet::ACCEPT_ENCODING_NO_GZIP] = true;
            $weight += 5;
        }
        if ($this->platformMismatch($ua, $h)) {
            $flags[BotSignalSet::UA_PLATFORM_MISMATCH] = true;
            $weight += 10;
        }

        $host = $r->host !== '' ? $r->host : (isset($h['host']) ? $h['host'] : '');
        if ($this->isBareIpHost($host)) {
            $flags[BotSignalSet::HOST_IS_BARE_IP] = true;
            $weight += 10;
        }

        return new BotSignalSet($flags, $weight, $uaClass, $this->structuralFingerprint($r->headers));
    }

    /**
     * True when the host header / request host is an IP literal rather than a domain name.
     */
    private function isBareIpHost(string $host): bool
    {
        $host = trim($host);
        if ($host === '') {
            return false;
        }

        // Direct IP check: covers raw IPv4 ('203.0.113.7') and unbracketed IPv6 ('2001:db8::1', '::1')
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        // Bracketed IPv6, with optional port: '[2001:db8::1]' or '[2001:db8::1]:443'
        if ($host[0] === '[') {
            $close = strrpos($host, ']');
            if ($close !== false) {
                $ip = substr($host, 1, $close - 1);
                $rest = substr($host, $close + 1);
                if ($rest === '' || preg_match('/^:\d+$/', $rest) === 1) {
                    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
                }
            }

            return false;
        }

        // IPv4 with port: '203.0.113.7:8080'
        if (substr_count($host, ':') === 1) {
            $parts = explode(':', $host, 2);
            if (preg_match('/^\d+$/', $parts[1]) === 1) {
                return filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            }
        }

        return false;
    }

    /**
     * @param array<string,string> $headers
     * @return array<string,string> name lower-cased (case-insensitive access)
     */
    private function lowercaseHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $out[strtolower((string) $name)] = (string) $value;
        }

        return $out;
    }

    /** Coarse UA class. Tool names are matched INPUT-side only and never emitted. */
    private function classifyUserAgent(string $ua): string
    {
        if ($ua === '') {
            return BotSignalSet::UA_EMPTY;
        }
        // Attack tools ONLY. This class is the one that acts without an opt-in, so an ordinary
        // HTTP client (python-httpx) or a commercial crawler (SemrushBot) must never be listed
        // here — they belong in the script and good-bot classes below.
        if (preg_match('/nmap|sqlmap|nuclei|nikto|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|feroxbuster|arachni|zaproxy/i', $ua) === 1) {
            return BotSignalSet::UA_SCANNER;
        }
        if (preg_match('#curl|wget|python-requests|python-urllib|python-httpx|urllib|go-http-client|libwww|okhttp|axios|node-fetch|guzzle|java/|apache-httpclient|ruby|perl|winhttp#i', $ua) === 1) {
            return BotSignalSet::UA_SCRIPT;
        }
        // Checked after scanner and script: a tool claiming to be Googlebot is a tool. Checked
        // before the browser test because most crawler UAs also contain "Mozilla".
        if (preg_match(
            '/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandex(bot|images|mobile)|'
            . 'applebot|facebookexternalhit|twitterbot|linkedinbot|pinterest(bot)?|'
            . 'discordbot|telegrambot|whatsapp|slackbot|redditbot|petalbot|seznambot|semrushbot/i',
            $ua
        ) === 1) {
            return BotSignalSet::UA_GOOD_BOT;
        }

        // The `Mozilla/` prefix, not a substring: real browsers and every major crawler UA start
        // with it, while an unknown tool merely containing "mozilla" is not a browser.
        if (strncasecmp($ua, 'Mozilla/', 8) === 0) {
            return BotSignalSet::UA_BROWSER;
        }

        return BotSignalSet::UA_UNKNOWN;
    }

    private function isHttp2(string $version): bool
    {
        return strncmp($version, '2', 1) === 0 || strncmp($version, '3', 1) === 0;
    }

    /**
     * UA-declared OS vs the Sec-CH-UA-Platform hint. A mismatch (UA says Windows, hint says Linux)
     * is a sharp forgery signal. Only fires when BOTH are known.
     *
     * @param array<string,string> $h lower-cased headers
     */
    private function platformMismatch(string $ua, array $h): bool
    {
        if (!isset($h['sec-ch-ua-platform'])) {
            return false;
        }
        $hint = strtolower(trim($h['sec-ch-ua-platform'], " \t\"'"));
        $uaOs = $this->userAgentOs($ua);
        if ($hint === '' || $uaOs === '') {
            return false;
        }
        // Normalize the hint to the UA vocabulary.
        if ($hint === 'macos') {
            $hint = 'mac';
        }

        return $hint !== $uaOs;
    }

    private function userAgentOs(string $ua): string
    {
        if (stripos($ua, 'windows') !== false) {
            return 'windows';
        }
        if (stripos($ua, 'android') !== false) {
            return 'android';
        }
        if (stripos($ua, 'iphone') !== false || stripos($ua, 'ipad') !== false) {
            return 'ios';
        }
        if (stripos($ua, 'mac os') !== false || stripos($ua, 'macintosh') !== false) {
            return 'mac';
        }
        if (stripos($ua, 'linux') !== false || stripos($ua, 'x11') !== false) {
            return 'linux';
        }

        return '';
    }

    /** Comma-list headers whose internal token order is not significant. */
    private const LIST_HEADERS = [
        'accept' => true,
        'accept-encoding' => true,
        'accept-language' => true,
        'accept-charset' => true,
        'connection' => true,
        'sec-ch-ua' => true,
        'te' => true,
        'cache-control' => true,
    ];

    /**
     * Digit-stripped, list-sorted structural header fingerprint (the JA4-H idea in PHP): strip
     * version digits from values and sort list-header tokens, so a Chromium version bump or a
     * reordered Accept keep the same fingerprint; header order + count still distinguish client
     * families (browser vs curl/python/Go). A feature on the Verdict, never an emitted value.
     *
     * @param array<string,string> $headers
     */
    private function structuralFingerprint(array $headers): string
    {
        $parts = [];
        foreach ($headers as $name => $value) {
            $lname = strtolower((string) $name);
            $v = preg_replace('/\d+/', '', (string) $value);
            if (isset(self::LIST_HEADERS[$lname])) {
                $tokens = array_map('trim', explode(',', (string) $v));
                sort($tokens);
                $v = implode(',', $tokens);
            }
            $parts[] = $lname . '=' . $v;
        }

        return count($headers) . ':' . implode('&', $parts);
    }

    /**
     * Resolve a request to an EXACT route entry with cheap fallbacks, so the GET-only index
     * still answers the POST/HEAD and slash/case variants scanners send (a third of
     * probes are POST). Order: exact match; then the GET bundle for the same path (for
     * POST/HEAD only — every other verb resolves exact-only here). OPTIONS/TRACE/PROPFIND
     * get their bounded generic answer from the method-coverage seam, not this resolver.
     *
     * @return array{0:string,1:array<string,mixed>}|null [routing key, entry]
     */
    private function resolveEntry(string $method, string $path): ?array
    {
        $upper = strtoupper($method);

        $methods = [$upper];
        if (($upper === 'POST' || $upper === 'HEAD') && !in_array('GET', $methods, true)) {
            $methods[] = 'GET';
        }

        foreach ($methods as $m) {
            foreach ($this->pathVariants($path) as $p) {
                $key = $m . ' ' . $p;
                $entry = $this->store->lookup($key);
                if ($entry !== null) {
                    return [$key, $entry];
                }
            }
        }

        return null;
    }

    /**
     * The bounded, ordered path variants a request resolves against — shared by resolveEntry() and
     * the method-coverage seam (FP-0011) so the two apply one path policy. In order: the normalized
     * path, its single trailing-slash toggle (except root), then its lowercased form when distinct.
     * No prefix, substring, recursive, decoded-second-pass or parameter matching — PathNormalizer's
     * byte-identity contract holds. Deduplicated, order preserved.
     *
     * @return string[]
     */
    private function pathVariants(string $path): array
    {
        $norm = PathNormalizer::normalize($path);

        $variants = [$norm];
        if ($norm !== '/') {
            $variants[] = substr($norm, -1) === '/' ? rtrim($norm, '/') : $norm . '/';
        }
        $lower = strtolower($norm);
        if ($lower !== $norm) {
            $variants[] = $lower;
        }

        return array_values(array_unique($variants));
    }

    /**
     * Bounded HTTP method coverage for OPTIONS/TRACE/PROPFIND on a servable compiled path (FP-0011),
     * or null when the path is uncovered, the host owns a real route, or the operator has silenced
     * the synthetic evidence — in which case classifyContent falls through to the parameter/attack
     * scan exactly as an uncovered miss does today.
     */
    private function methodCoverageVerdict(RequestContext $r, string $method, int $anomaly, BotSignalSet $signals, SiteProfile $profile): ?Verdict
    {
        // Asterisk-form OPTIONS * is server-wide negotiation, never a path — reject the raw target
        // before PathNormalizer::normalize() prefixes a slash and turns it into /*.
        if (trim($r->path) === '*') {
            return null;
        }

        $cap = $this->methodCapability($r->path);
        if ($cap === null) {
            return null;
        }
        $canonical = $cap['path'];

        // Never shadow a genuine host route: if the profile declares one for the incoming or the
        // canonical path under the incoming method or any advertised method, decline. On the
        // standalone/fallback position the profile is empty, so this never fires there.
        $incomingNorm = PathNormalizer::normalize($r->path);
        $probeMethods = array_values(array_unique(array_merge([$method], $cap['methods'])));
        foreach (array_unique([$incomingNorm, $canonical]) as $p) {
            foreach ($probeMethods as $m) {
                if ($profile->hasRoute($m, $p)) {
                    return null;
                }
            }
        }

        // Ignore-from-detection (Config->ignoreTemplates): the synthetic id or either tag silences
        // both the evidence and the handle, so the request is no longer a probe here.
        if ($this->methodIgnored($method)) {
            return null;
        }

        $match = $this->methodMatch($method);
        $detection = new Detection(true, [$match], $method . ' ' . $canonical, $match->severity);
        $handle = FakeHandle::method($method . ' ' . $canonical);

        // Root negotiation can be routine, so a generic OPTIONS / is the one CLEAN method verdict —
        // it still carries its information detection and method handle. OPTIONS on every other
        // covered path, and TRACE/PROPFIND everywhere, are scanner probes.
        $classification = ($method === 'OPTIONS' && $canonical === '/') ? Verdict::CLEAN : Verdict::SCANNER_PROBE;

        return new Verdict($classification, $detection, $match->severity, $anomaly, $signals, $handle);
    }

    /**
     * The bounded method capability of a compiled path (FP-0011): the canonical path variant that
     * carries coverage, its Allow header value and the advertised verb list, or null when no variant
     * has an eligible non-OPTIONS route. Variant-major, mirroring "never union case/slash variants
     * that could represent different resources": the FIRST path variant (normalized, trailing-slash
     * toggle, lowercase) with a non-OPTIONS capability wins, and every verb is computed only at that
     * one canonical variant.
     *
     * @return array{path:string,allow:string,methods:string[]}|null
     */
    private function methodCapability(string $path): ?array
    {
        foreach ($this->pathVariants($path) as $variant) {
            $methods = $this->effectiveMethods($variant);
            // OPTIONS alone is this responder's own verb and never, by itself, makes a path covered.
            $nonOptions = array_filter($methods, static function (string $m): bool {
                return $m !== 'OPTIONS';
            });
            if ($nonOptions !== []) {
                return ['path' => $variant, 'allow' => implode(', ', $methods), 'methods' => $methods];
            }
        }

        return null;
    }

    /**
     * The canonical-ordered advertised methods at EXACTLY $path, always including OPTIONS (which this
     * responder implements). Every other verb appears only when its exact route — or, for HEAD/POST,
     * the documented GET fallback — is eligible. Final order per spec:
     * GET, HEAD, POST, PUT, DELETE, PATCH, OPTIONS, TRACE, PURGE.
     *
     * @return string[]
     */
    private function effectiveMethods(string $path): array
    {
        $eligible = [];
        // Probe order for eligibility (spec §2); OPTIONS is not probed, it is always advertised.
        foreach (['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'TRACE', 'PURGE'] as $verb) {
            if ($this->verbEligible($verb, $path)) {
                $eligible[$verb] = true;
            }
        }

        $out = [];
        foreach (['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'PURGE'] as $verb) {
            if ($verb === 'OPTIONS' || isset($eligible[$verb])) {
                $out[] = $verb;
            }
        }

        return $out;
    }

    /**
     * Whether $verb has an eligible route at EXACTLY $path. An exact key is eligible on its own
     * merits; only HEAD/POST fall back to the GET bundle, mirroring resolveEntry — and only when no
     * exact key exists for the verb, so an exact-but-ineligible HEAD/POST entry blocks the fallback
     * (today's resolve-then-decline behavior) rather than silently borrowing GET.
     */
    private function verbEligible(string $verb, string $path): bool
    {
        $key = $verb . ' ' . $path;
        $entry = $this->store->lookup($key);
        if ($entry !== null) {
            return $this->entryEligible($key, $entry);
        }

        if ($verb === 'HEAD' || $verb === 'POST') {
            $getKey = 'GET ' . $path;
            $get = $this->store->lookup($getKey);

            return $get !== null && $this->entryEligible($getKey, $get);
        }

        return false;
    }

    /**
     * An exact route entry is eligible when the current corpus flag / severity ceiling / exclude set
     * leave at least one servable candidate AND its post-ignoreTemplates detection is non-empty — so
     * a route the operator has fully excluded or ignored never advertises a method.
     *
     * @param array<string,mixed> $entry
     */
    private function entryEligible(string $key, array $entry): bool
    {
        if ($this->candidates($entry['b'] ?? []) === []) {
            return false;
        }

        return !$this->detectionFor($key, $this->detectIds($entry))->isEmpty();
    }

    /**
     * The fixed synthetic evidence for a method-coverage verb. Information severity; the id/name are
     * telemetry only and never a served byte, so they carry no scanner-matcher signature. The cluster
     * key (verb + canonical path) is set by the caller.
     */
    private function methodMatch(string $method): TemplateMatch
    {
        static $meta = [
            'OPTIONS' => ['http-method-options', 'HTTP OPTIONS method discovery'],
            'TRACE' => ['http-method-trace', 'HTTP TRACE method probe'],
            'PROPFIND' => ['http-method-propfind', 'HTTP WebDAV method probe'],
        ];
        [$id, $name] = $meta[$method];

        return new TemplateMatch($id, 'info', ['scanner-coverage', 'http-methods'], $name);
    }

    /**
     * True when the operator has silenced this verb's synthetic evidence by id or by either tag.
     * The synthetic id has no store meta, so membership is tested against the constant id/tag list
     * directly — applyIgnore()/isExcluded() resolve tags through store->template() and would never
     * match it.
     */
    private function methodIgnored(string $method): bool
    {
        if ($this->ignoreTemplates === []) {
            return false;
        }

        return $this->methodDenied($this->methodMatch($method), $this->ignoreTemplates);
    }

    /**
     * True when the serving exclude set names this verb's synthetic id or either tag — detection is
     * permitted (classify still fires) but synthesis declines, matching the ignore/exclude split.
     */
    private function methodExcluded(string $method): bool
    {
        if ($this->effectiveExclude === []) {
            return false;
        }

        return $this->methodDenied($this->methodMatch($method), array_flip($this->effectiveExclude));
    }

    /**
     * Shared id-or-tag membership test for a synthetic method match against a flipped deny set.
     *
     * @param array<string,int> $deny
     */
    private function methodDenied(TemplateMatch $match, array $deny): bool
    {
        if (isset($deny[$match->id])) {
            return true;
        }
        foreach ($match->tags as $tag) {
            if (isset($deny[$tag])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Back-compat facade over classify() + synthesize() (two-phase design §6.6). Core is
     * position-blind and action-free; this method layers the LEGACY Config gates + Observer +
     * serve-delay back on so the existing app (and this suite) keep byte-identical behavior until
     * the caller migrates to funnypot-policy. New consumers call classify()/synthesize() directly.
     */
    public function respond(RequestContext $r): ?SynthesizedResponse
    {
        // Ground-truth switches first: a tripped kill switch or a trusted scanner must NEVER see a
        // fake, and respond mode must be explicitly enabled. No observer, no work (as before).
        if ($this->config->killSwitchTripped() || !$this->config->respondEnabled() || $this->config->isTrusted($r)) {
            return null;
        }

        // FALLBACK position: no real app behind the engine, so an empty SiteProfile.
        $verdict = $this->classify($r, SiteProfile::empty());
        $seed = $this->config->seedFor($r);

        if ($verdict->classification === Verdict::ATTACK_CLASS) {
            return $this->respondAttack($r, $verdict, $seed);
        }

        $handle = $verdict->fakeHandle;
        if ($handle === null || ($handle->kind !== FakeHandle::KIND_ROUTE && $handle->kind !== FakeHandle::KIND_METHOD)) {
            // A genuine miss / real route / empty entry: the app serves its own 404. Exception: a
            // signal-only probe (OAST/SSRF or Log4Shell/JNDI) folds a detection onto a null-handle
            // verdict (SCANNER_PROBE, nothing to serve). Surface it so the app can score the spray.
            // Pre-fold this branch was reached only with an empty detection, so this fires ONLY for the
            // signal-only fold case — no double-fire (routed/attack coincidences already fire
            // onDetection below / in respondAttack).
            if (!$verdict->detection->isEmpty()) {
                $this->safeOnDetection($r, $verdict->detection);
            }
            return null;
        }

        // A routed probe. Detection covers EVERY routed template (the full 'd' id-list); signal
        // the app before any serve decision.
        $this->safeOnDetection($r, $verdict->detection);

        if (!$this->config->gateOpen($r)) {
            return $this->declined($r, Outcome::GATE_CLOSED);
        }

        // Root / homepage-class ROUTE entries (classified clean) never fake-vuln an ordinary visitor
        // unless the app's probe-signature predicate says so. A CLEAN method handle (generic
        // OPTIONS /) is exempt: a 204 + honest Allow is protocol negotiation, not a fabricated
        // vulnerability, so it may negotiate on a standalone honeypot without a probe signature.
        if ($verdict->classification === Verdict::CLEAN
            && $handle->kind === FakeHandle::KIND_ROUTE
            && !$this->config->hasProbeSignature($r)) {
            return $this->declined($r, Outcome::NO_SIGNATURE);
        }

        $built = $this->buildFake($verdict->fakeHandle, SiteProfile::empty(), $seed, $r);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        if (!$this->safeShouldRespond($r, $verdict->detection)) {
            return $this->declined($r, Outcome::VETOED);
        }

        // Surface the winning handle to the app (debug tooling). Inert: never emitted (see
        // SynthesizedResponse::$servedBy).
        $built['r']->servedBy = $handle;

        // FP-0252: carry the tarpit delay as metadata for the emitter/adapter to apply at the
        // transport edge — core no longer sleeps inside the host worker. Computed here so jitter is
        // still drawn per served response; inert (never serialized into served bytes).
        $built['r']->delayMicros = $this->config->serveDelayMicros();
        $this->safeOnOutcome($r, $built['r'], Outcome::SERVED);

        return $built['r'];
    }

    /**
     * The attack-class branch of the facade. Emulation bypasses the app-suspicion gate (an
     * injection payload is its own signal), exactly as the legacy path did; kill-switch / mode /
     * trusted are already applied above.
     */
    private function respondAttack(RequestContext $r, Verdict $verdict, string $seed): ?SynthesizedResponse
    {
        $this->safeOnDetection($r, $verdict->detection);

        $built = $this->buildFake($verdict->fakeHandle, SiteProfile::empty(), $seed, $r);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        // Surface the winning handle to the app (debug tooling). Inert: never emitted (see
        // SynthesizedResponse::$servedBy).
        $built['r']->servedBy = $verdict->fakeHandle;

        // FP-0252: tarpit delay as metadata (see respond()); the in-core usleep is gone.
        $built['r']->delayMicros = $this->config->serveDelayMicros();
        $this->safeOnOutcome($r, $built['r'], Outcome::SERVED);

        return $built['r'];
    }

    /**
     * Build a fake from a Verdict's fakeHandle (two-phase design §2.2). Invoked only when the
     * caller's policy chose to deceive — core never decides that. Pure function of (verdict,
     * profile, seed) + the compiled store: same inputs => same bytes. null is the sole "no fake"
     * signal (degrade to the caller's 404); a synthesis fault never escapes as a 5xx.
     */
    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?SynthesizedResponse
    {
        return $this->buildFake($verdict->fakeHandle, $profile, $seed)['r'];
    }

    public function synthesizeFromHandle(?FakeHandle $handle, SiteProfile $profile, string $seed): ?SynthesizedResponse
    {
        return $this->buildFake($handle, $profile, $seed)['r'];
    }

    private function declined(RequestContext $r, string $reason): ?SynthesizedResponse
    {
        $this->safeOnOutcome($r, null, $reason);

        return null;
    }

    /**
     * FP-0252 fail-safe wrappers around the host-supplied Observer. A buggy app callback that throws
     * must never turn a would-be 404 into a host 500, so every Observer call goes through these:
     *  - onDetection throw ⇒ swallowed (signal loss only; the serving decision is unaffected).
     *  - shouldRespond throw ⇒ treated as a veto (false), so respond() declines with Outcome::VETOED
     *    — surfaced to a working observer via the wrapped onOutcome below.
     *  - onOutcome throw ⇒ swallowed (incl. inside declined(), so the veto path never re-throws).
     * Silent by design: core does no I/O, so there is nowhere to log. Determinism is unaffected —
     * same inputs, same throw, same fallback.
     */
    private function safeOnDetection(RequestContext $r, Detection $detection): void
    {
        try {
            $this->observer->onDetection($r, $detection);
        } catch (\Throwable $e) {
            // Swallow: signal loss only.
        }
    }

    private function safeShouldRespond(RequestContext $r, Detection $detection): bool
    {
        try {
            return $this->observer->shouldRespond($r, $detection);
        } catch (\Throwable $e) {
            return false;
        }
    }

    private function safeOnOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
        try {
            $this->observer->onOutcome($r, $response, $reason);
        } catch (\Throwable $e) {
            // Swallow: the outcome signal is best-effort; a throw here must not escape core.
        }
    }

    /**
     * The synthesis core shared by synthesize() and the respond() facade: turn a fakeHandle into
     * a fake or a decline reason. Content-integrity only (candidates / persona / ceiling / exclude
     * / size cap for a route; render + ceiling + cap for an attack) — no gates, no observer, no
     * delay. The WHEN/whether/side-effect decisions are the caller's (the facade / the policy).
     *
     * $r is the live request, threaded ONLY on the facade path (respond) so a behavior primitive
     * can consult it; the position-blind port (synthesize) leaves it null and any request-aware
     * behavior degrades to its request-free default. It never affects route/persona synthesis.
     *
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildFake(?FakeHandle $handle, SiteProfile $profile, string $seed, ?RequestContext $r = null): array
    {
        if ($handle === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }
        if ($handle->kind === FakeHandle::KIND_ROUTE) {
            $built = $this->buildRouteFake($handle, $profile, $seed, $r);
        } elseif ($handle->kind === FakeHandle::KIND_ATTACK) {
            $built = $this->buildAttackFake($handle, $seed, $r);
        } elseif ($handle->kind === FakeHandle::KIND_METHOD) {
            $built = $this->buildMethodFake($handle, $profile);
        } else {
            // Unknown / llm kinds are host-injected synthesizers; core builds nothing.
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }

        // Single convergence point: every served fake gets the same front-layer envelope, so the
        // route (synthesizer) path and the attack-template path are indistinguishable by it. Without
        // this, attack fakes shipped no X-Request-Id and its absence marked the branch as canned.
        if ($built['r'] !== null) {
            $this->stampEnvelope($built['r']);
        }

        return $built;
    }

    /**
     * Stamp the cosmetic front-layer headers a real proxy/app adds to every response: a
     * per-request X-Request-Id (16 hex, like a real edge) plus the deploy's coherent Server /
     * X-Powered-By identity. Each is guarded so a value the synthesizer or an emulator already set
     * is never overwritten — the route path stamps these itself, so this only fills the attack-
     * template path (and any future branch) without double-stamping. Pure hex is CR/LF/NUL-safe,
     * so X-Request-Id never trips the C8 header guard.
     */
    private function stampEnvelope(SynthesizedResponse $response): void
    {
        $headers = $response->headers;

        if ($this->config->serverHeader !== null && !isset($headers['Server'])) {
            $headers['Server'] = $this->config->serverHeader;
        }
        if ($this->config->poweredBy !== null && !isset($headers['X-Powered-By'])) {
            $headers['X-Powered-By'] = $this->config->poweredBy;
        }
        if (!isset($headers['X-Request-Id'])) {
            $headers['X-Request-Id'] = bin2hex(random_bytes(8));
        }

        $response->headers = $headers;
    }

    /**
     * The runtime egress fingerprint guard, lazily loaded once from the package denylist. null ⇒
     * the denylist could not load; the caller treats that as "cannot verify" and fails closed to
     * the plain 404 (never a 5xx — a 500 is itself a tell). The load-once result is cached so a
     * broken denylist is not re-required per request.
     */
    private function runtimeGuard(): ?FingerprintGuard
    {
        if (!$this->runtimeGuardLoaded) {
            $this->runtimeGuardLoaded = true;
            $this->runtimeGuard = FingerprintGuard::tryFromPackage();
        }

        return $this->runtimeGuard;
    }

    /**
     * Test seam: inject the runtime egress guard (or null to simulate an unavailable denylist so the
     * fail-closed path can be exercised). Mirrors RulesUpdater::setNowForTesting().
     */
    public function setFingerprintGuardForTesting(?FingerprintGuard $guard): void
    {
        $this->runtimeGuardLoaded = true;
        $this->runtimeGuard = $guard;
    }

    /**
     * Egress fingerprint-safety screen: true ⇒ the built response is clean (or the scan is off, or
     * the rule reflects attacker captures so scanning it would be a reflected-byte oracle). false ⇒
     * a detector signature reached the built bytes, OR the rule is non-reflecting but the guard
     * could not load — either way the caller declines with Outcome::FINGERPRINT_LEAK. A rule that
     * reflects captures ($rule null for the route path, which never reflects request bytes) is
     * always passed unscanned; its authored bytes are covered by the static gate and its runtime
     * bytes by the render-corpus gate.
     *
     * @param array<string,mixed>|null $rule the attack rule (null on the route path)
     */
    private function egressClean(SynthesizedResponse $response, ?array $rule): bool
    {
        if (!$this->config->runtimeFingerprintScan) {
            return true;
        }
        if ($rule !== null && $this->ruleReflects($rule)) {
            return true;
        }
        $guard = $this->runtimeGuard();
        if ($guard === null) {
            return false; // cannot verify ⇒ fail closed
        }

        return $guard->scanResponse($response->body, $response->headers) === [];
    }

    /**
     * @param array<string,mixed> $rule
     */
    private function ruleReflects(array $rule): bool
    {
        $id = (string) ($rule['id'] ?? '');
        if ($id === '') {
            return ServedStringWalker::reflectsCaptures($rule);
        }
        if (!isset($this->reflectorCache[$id])) {
            $this->reflectorCache[$id] = ServedStringWalker::reflectsCaptures($rule);
        }

        return $this->reflectorCache[$id];
    }

    /**
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildRouteFake(FakeHandle $handle, SiteProfile $profile, string $seed, ?RequestContext $r = null): array
    {
        $key = (string) $handle->key;

        // Never shadow a declared real route (BEFORE position). The key is '<METHOD> <path>'.
        $sp = strpos($key, ' ');
        if ($sp !== false && $profile->hasRoute(substr($key, 0, $sp), substr($key, $sp + 1))) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $entry = $this->store->lookup($key);
        $allBundles = $entry === null ? [] : ($entry['b'] ?? []);

        // Filter to servable candidates BEFORE the persona pick: excluded bundles and bundles
        // above the severity ceiling are removed so a seed never lands on a refused bundle.
        $candidates = $this->candidates($allBundles);
        if ($candidates === []) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $bundle = PersonaSelector::pick($candidates, $seed);
        if ($bundle === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $satisfies = $this->detectionFor($key, $bundle['t'] ?? []);
        // Thread the resolved store key so a route-key-guarded template dresses only its own route
        // (path-aware directory listings). The key is the handle's, never request-derived, so facade
        // and position-blind port stay byte-equivalent.
        $response = $this->synthesizer->synthesize($bundle, $satisfies, $seed, $key);
        if ($response === null) {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }

        // Egress fingerprint screen on the BASE synthesized response (route synthesis never resolves
        // request bytes, so it is non-reflecting and always scannable). The reflecting param reaction
        // appended below carries its own guard, so it is deliberately screened there, not here.
        if (!$this->egressClean($response, null)) {
            return ['r' => null, 'reason' => Outcome::FINGERPRINT_LEAK];
        }

        // FP-0157: append an inert query reaction when the handle carries a validated intent and the
        // reflecting-decoy gate is open for this request. It returns a NEW response or null; on null
        // (any decline, a null-request port, config off, an ineligible bundle/response) the base
        // response is kept unchanged, so opting in never reduces route coverage.
        $decorated = $this->reactions->decorate($response, $bundle, $handle, $r);
        if ($decorated !== null) {
            $response = $decorated;
        }

        // Never emit an oversized body (no tarpit/amplifier unless the app opts in).
        if (strlen($response->body) > $this->config->maxBodyBytes) {
            return ['r' => null, 'reason' => Outcome::OVER_CAP];
        }

        return ['r' => $response, 'reason' => Outcome::SERVED];
    }

    /**
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildAttackFake(FakeHandle $handle, string $seed, ?RequestContext $r = null): array
    {
        if ($this->attackEmulator === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $rule = $this->attackEmulator->ruleById((string) $handle->ruleId);
        if ($rule === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        // A decoy that reflects attacker request bytes into an active context (an HTML body or a
        // redirect Location) is safe bait only from an isolated origin; inline in a response-owning
        // host it would be a live XSS/open-redirect in that host's real origin. classify() already
        // ran, so the detection/intel is captured — this only withholds the reflection. Covers both
        // the attack tier and the param tier: a matched param route rides an attack handle and
        // ruleById() resolves param entries here too. serveReflector() AND-composes the global
        // isolatedOrigin posture, the per-class knob (Config::$reflectClasses) and the request-bound
        // authorizer (Config::$reflectorAuthorizer): every term can only subtract, so an embedded host
        // never reflects and neither does an isolated one that supplies no evidence. $r is the live
        // request on the facade path and null on the position-blind port — a null request carries no
        // evidence, so synthesize() suppresses every reflector by construction. A rule with no
        // reflect_class falls back to 'default' (absent from the map ⇒ enabled), keeping any untagged
        // reflector fail-safe under the same three-term gate.
        if (!empty($rule['reflects_input'])
            && !$this->config->serveReflector((string) ($rule['reflect_class'] ?? 'default'), $r)) {
            return ['r' => null, 'reason' => Outcome::REFLECTION_SUPPRESSED];
        }

        // Seed fake values from the persona so a given attacker sees stable, but per-attacker
        // distinct, fabricated secrets (not one shared seed-0 value that would fingerprint). $r is
        // present only on the facade path; the port leaves it null (behavior renders its default).
        $response = $this->attackEmulator->renderRule($rule, $handle->captures, crc32($seed), $r);
        if ($response === null) {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE]; // CRLF header-split guard
        }
        // Egress fingerprint screen on the built body + headers, UNLESS the rule reflects attacker
        // captures — scanning reflected bytes would make the guard a two-request oracle. A hit on a
        // non-reflecting rule (or a guard that could not load) fails closed to the plain 404.
        if (!$this->egressClean($response, $rule)) {
            return ['r' => null, 'reason' => Outcome::FINGERPRINT_LEAK];
        }
        if (Severity::exceeds($response->satisfies->highestSeverity, $this->config->severityCeiling)) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }
        if (strlen($response->body) > $this->config->maxBodyBytes) {
            return ['r' => null, 'reason' => Outcome::OVER_CAP];
        }

        return ['r' => $response, 'reason' => Outcome::SERVED];
    }

    /**
     * Synthesize a bounded HTTP method-coverage response from a KIND_METHOD handle (FP-0011): a
     * closed 204 (OPTIONS) or 405 (TRACE/PROPFIND) carrying only a canonical Allow list built from
     * closed verb constants. Nothing is derived from the request headers, query, body or Host, so a
     * malformed, tampered or stale handle can only fail closed to a 404 — never a 5xx and never a
     * broadened response.
     *
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildMethodFake(FakeHandle $handle, SiteProfile $profile): array
    {
        $key = (string) $handle->key;
        $sp = strpos($key, ' ');
        if ($sp === false) {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }
        $method = substr($key, 0, $sp);
        $path = substr($key, $sp + 1);

        // Closed key grammar: one of the three implemented verbs, a rooted canonical path, never the
        // asterisk form. Anything else is a tampered handle.
        if (($method !== 'OPTIONS' && $method !== 'TRACE' && $method !== 'PROPFIND')
            || $path === '' || $path[0] !== '/' || $path === '/*') {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }

        // An exact authored route for this verb that appeared since classification owns the path; the
        // generic fallback must never shadow it.
        if ($this->store->lookup($key) !== null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        // Re-derive capability from the CURRENT store/config: a stale handle whose canonical path has
        // lost its last eligible route (corpus off, ceiling lowered, templates excluded) or whose
        // coverage now lands on a different variant is no longer covered.
        $cap = $this->methodCapability($path);
        if ($cap === null || $cap['path'] !== $path) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        // Repeat the real-route veto so a route that went live after classification cannot be shadowed.
        $probeMethods = array_values(array_unique(array_merge([$method], $cap['methods'])));
        foreach ($probeMethods as $m) {
            if ($profile->hasRoute($m, $path)) {
                return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
            }
        }

        // Exclude declines synthesis for the synthetic id/tags (detection was still permitted).
        if ($this->methodExcluded($method)) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $match = $this->methodMatch($method);
        $detection = new Detection(true, [$match], $method . ' ' . $path, $match->severity);

        if ($method === 'OPTIONS') {
            // 204: RFC 9110 §8.6 forbids Content-Length here, so it is deliberately omitted; the
            // emitter suppresses a synthesized one for 204. No Content-Type/CORS/DAV/reflection byte.
            return ['r' => new SynthesizedResponse(204, ['Allow' => $cap['allow']], '', $detection), 'reason' => Outcome::SERVED];
        }

        // TRACE/PROPFIND: method not allowed. Explicit Content-Length: 0 (never a synthesized one);
        // the generic responder never fabricates WebDAV 207 behavior.
        return ['r' => new SynthesizedResponse(405, ['Allow' => $cap['allow'], 'Content-Length' => '0'], '', $detection), 'reason' => Outcome::SERVED];
    }

    /**
     * Servable bundles: not excluded, and at or below the severity ceiling. No cost
     * for the exclude pass when the deny list is empty.
     *
     * @param array<int,array<string,mixed>> $bundles
     * @return array<int,array<string,mixed>>
     */
    private function candidates(array $bundles): array
    {
        $ceiling = $this->config->severityCeiling;
        $deny = $this->effectiveExclude === [] ? null : array_flip($this->effectiveExclude);

        $kept = [];
        foreach ($bundles as $bundle) {
            // Corpus reflection off: drop nuclei-derived bundles but keep folded product decoys
            // (their pid is route-*), which are a separately-toggled capability.
            if (!$this->nucleiEnabled && strncmp((string) ($bundle['pid'] ?? ''), 'route-', 6) !== 0) {
                continue;
            }
            if (Severity::exceeds((string) ($bundle['sev'] ?? 'unknown'), $ceiling)) {
                continue;
            }
            if ($deny !== null && $this->isExcluded($bundle, $deny)) {
                continue;
            }
            $kept[] = $bundle;
        }

        return $kept;
    }

    /**
     * True when a bundle names an excluded template id, product, or tag. Coarse by
     * design: exclude means "never serve this persona".
     *
     * @param array<string,mixed> $bundle
     * @param array<string,int>   $deny
     */
    private function isExcluded(array $bundle, array $deny): bool
    {
        if (isset($deny[$bundle['pid'] ?? ''])) {
            return true;
        }
        foreach ($bundle['t'] ?? [] as $id) {
            if (isset($deny[$id])) {
                return true;
            }
            $meta = $this->store->template($id);
            foreach ((array) ($meta['tags'] ?? []) as $tag) {
                if (isset($deny[$tag])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The full detect id-list for an entry: the explicit `'d'` list on a capped key, or
     * the union of the served bundles' template ids everywhere else. Capping the served
     * ('b') set never trims detect — a one-line, backward-compatible read (the Phase-1
     * fixture has no `'d'`, so it falls back to the union).
     *
     * @param array<string,mixed> $entry
     * @return string[]
     */
    private function detectIds(array $entry): array
    {
        if (isset($entry['d'])) {
            return $this->applyIgnore($entry['d']);
        }

        $ids = [];
        foreach ($entry['b'] ?? [] as $bundle) {
            foreach ($bundle['t'] ?? [] as $id) {
                $ids[] = $id;
            }
        }

        return $this->applyIgnore($ids);
    }

    /**
     * Drop template ids the host has marked ignore-from-detection (Config->ignoreTemplates): an id
     * named directly, or one whose template carries an ignored tag. Detection-only — it never
     * changes which bundles are served (that is Config->exclude's separate job). When the set is
     * empty the list is returned unchanged, so a host that does not use the feature pays nothing.
     *
     * Drop-from-evidence: an ignored id simply contributes no evidence; any remaining id still
     * drives the detection. classify() reads the emptied result and degrades that entry to CLEAN.
     *
     * @param string[] $ids
     * @return string[]
     */
    private function applyIgnore(array $ids): array
    {
        if ($this->ignoreTemplates === []) {
            return $ids;
        }

        $kept = [];
        foreach ($ids as $id) {
            if (isset($this->ignoreTemplates[$id])) {
                continue;
            }
            $meta = $this->store->template($id);
            $byTag = false;
            foreach ((array) ($meta['tags'] ?? []) as $tag) {
                if (isset($this->ignoreTemplates[$tag])) {
                    $byTag = true;
                    break;
                }
            }
            if (!$byTag) {
                $kept[] = $id;
            }
        }

        return $kept;
    }

    /**
     * Build a Detection covering a flat list of template ids (deduped, in order).
     *
     * @param string[] $ids
     */
    private function detectionFor(string $key, array $ids): Detection
    {
        $matches = [];
        $seen = [];
        $ceiling = '';
        foreach ($ids as $id) {
            if (isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;

            $meta = $this->store->template($id);
            if ($meta === null) {
                continue;
            }

            $severity = (string) ($meta['sev'] ?? 'unknown');
            $matches[] = new TemplateMatch(
                $id,
                $severity,
                (array) ($meta['tags'] ?? []),
                (string) ($meta['name'] ?? '')
            );
            $ceiling = $ceiling === '' ? $severity : Severity::ceiling($ceiling, $severity);
        }

        if ($matches === []) {
            return Detection::none();
        }

        return new Detection(true, $matches, $key, $ceiling);
    }
}
