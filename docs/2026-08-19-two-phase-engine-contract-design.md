# funnypot-core · two-phase engine contract (classify + synthesize) — design

**Status:** draft for build · **Date:** 2026-08-19 · **Piece:** the funnypot-core half of decision **M**
(position-blind engine + `funnypot-policy` package + deceptive-WAF).
**Source of truth:** `funnypot-mainnet/docs/2026-08-19-program-decisions.md` §M. Where this doc and §M
disagree, §M wins and this doc is corrected. The companion `…-plan.md` executes this design and does not
redesign it.

This design splits funnypot-core's single `respond()` path into a **two-phase contract** —
`classify(request, SiteProfile) → Verdict` (cheap, content-detection only, always safe) and
`synthesize(verdict, SiteProfile, seed) → FakeResponse` (invoked only when the caller's policy chooses to
deceive). The engine becomes **position-blind and action-free**: it never blocks, reports, logs, delays,
or knows whether it sits before or after the app's real routes. All of that moves up to `funnypot-policy`
(decision M3); the deception content — nuclei-inversion, template/attack fakes, STYLE — is **fully
retained** and becomes the body of `synthesize()`.

---

## 1. Orientation — what exists today (grounded)

Single entrypoint on `Funnypot\Honeypot` (`src/Honeypot.php`), which implements `Funnypot\Engine`:

- **`detect(RequestContext): Detection`** — cheap route resolution (`resolveEntry`: exact → GET-fallback
  for POST/HEAD → trailing-slash / lower-case variants) → `detectionFor()` builds a `Detection` (matched
  `TemplateMatch[]`, cluster key, highest severity). Side-effect-free. This is *almost* `classify()` today
  — but it only covers **routed nuclei templates**; it does not run the attack-payload matcher, and it
  emits nothing about anomaly beyond the template severity.
- **`respond(RequestContext): ?SynthesizedResponse`** — the single fused path. In order:
  1. **WHEN/whether gates** (policy-shaped): `killSwitchTripped()`, `respondEnabled()` (mode), `isTrusted()`.
  2. `resolveEntry()`; on a **miss** → `tryAttack()` (the CRS attack-class fallback).
  3. `detectionFor()` + `observer->onDetection()` (side-effect seam).
  4. `gateOpen()` (app suspicion predicate) → `declined(GATE_CLOSED)`.
  5. **synthesis-integrity filtering**: `candidates()` (drop excluded / nuclei-off / above severity
     ceiling) → `PersonaSelector::pick(seed)` → sig=1 root guard (`hasProbeSignature`).
  6. `observer->shouldRespond()` veto seam.
  7. `synthesizer->synthesize(bundle, satisfies, seed)` → size cap → `serveDelayMicros()` (usleep) →
     `observer->onOutcome(SERVED)`.
- Two **synthesis engines already isolated as objects**, both returning `SynthesizedResponse`:
  - `Synthesis\ResponseSynthesizer` — one compiled nuclei bundle → a matcher-satisfying fake; owns the
    STYLE emulator layer (`Response\EmulatorRegistry`, realistic `.env`/`.git`, etc.) with a strict
    validate-or-fall-back to minimal synthesis.
  - `Template\TemplateAttackEmulator::emulate(RequestContext, int seed)` — data-driven LFI/SQLi/SSTI/
    cmd-injection/XSS emulation, first matching rule wins, rendered via the bounded `DirectiveRenderer`.
- **`Config`** (`src/Config.php`) fuses two unrelated concern-sets: (a) WHEN/whether-to-serve **policy**
  closures — `gate`, `killSwitch`, `trustedBypass`, `mode`, `probeSignature`, `latencyMs/jitter`; and (b)
  **synthesis** knobs — `responseStyle`, `severityCeiling`, `maxBodyBytes`, `exclude`, `nucleiReflection`,
  `serverHeader`, `poweredBy`, `personaSeed`/`seedSalt`. The two-phase split cleaves along exactly this seam.
- **`Observer`** (`onDetection` / `shouldRespond` / `onOutcome`) is the side-effect seam the app uses to
  log/score/veto. In the two-phase world this is the **policy's** job.
- The app entrypoint `Funnypot\App\Http\HoneypotController::handle()` (`funnypot/src/App/Http/…`)
  constructs a `respond`-mode `Config` with `gate: fn()=>true` (standalone honeypot deceives everything
  hostile-looking), calls `detect()` **and** `respond()`, logs, emits, then — **on an engine miss** —
  calls the app-side `LlmFakeResponder` and finally a plain 404.

### The one honest tension with §M

Decision M2 says `synthesize()` "owns the nuclei-inversion / **LLM** / template fakes." Grounded reality:
**the LLM fake is not in core** — it is `Funnypot\App\Llm\LlmFakeResponder`, an app-side precedence layer
that runs *after* an engine miss (ARCHITECTURE.md precedence 3, below nuclei/CRS). Core owns
nuclei-inversion + template/attack fakes + STYLE only.

This design does **not** move the LLM into core in v1 (that would drag the app's sidecar HTTP client,
cache, and probe-gate into a framework-free library and is out of scope). Instead:

- `synthesize()` owns the **engine-native** deception it already has (nuclei + attack + STYLE), exactly
  as M2 intends for that content.
- The LLM fake is modeled as **one more synthesis strategy behind the same `FakeResponse` shape**, wired
  by the caller. The policy's `Decision.fakeHandle` can name the LLM strategy; the thin app adapter
  (decision M ripple "D/E consume via a thin adapter") supplies the LLM responder. So the *contract* is
  "synthesize a `FakeResponse`", and the LLM is a pluggable synthesizer the host injects — §M's intent
  (deception content lives behind synthesize) is honored without relocating the sidecar client into core.
- **Recorded as a follow-up**, not a v1 core change. Noted here so the split does not foreclose it.

---

## 2. The two-phase contract

### 2.1 `classify(RequestContext $r, SiteProfile $profile): Verdict`

Cheap, **always safe to call**, **content-detection only**, **no side effects, no gates, no I/O**. It is
today's `detect()` widened to also run the attack-payload matcher and to consult the `SiteProfile`
real-route oracle. It answers one question: *what is this request, as content?* — never *should we act?*

```
Verdict {
    classification: clean | scanner-probe | attack-class | suspicious   // string enum (7.3: const strings)
    detection:      Detection            // matched template/attack ids + severity + tags (existing type)
    severity:       string               // highest nuclei severity across the match ('' when none)
    anomaly:        int                  // cheap cumulative anomaly score (0 when clean); folds the §2.4 request-shape bot-signal weights; NEVER alone a deceive trigger — see M6 / S2
    signals:        BotSignalSet         // computed request-shape signal set (decision S); pure data; read by the policy AND carried as telemetry (decision T); INPUT-side only, never emitted → fingerprint-safe
    fakeHandle:     FakeHandle|null      // opaque, serializable pointer to what synthesize() would build; null when nothing to fake
}
```

- **`classification`** maps the match:
  - `clean` — no template routes and no attack payload; **or** a sig=1 root/homepage hit with no probe
    signature (an ordinary visitor to `/`), **or** the path is a real route per `SiteProfile` (see below).
  - `scanner-probe` — a routed nuclei template matched (a known scanner signature hit a known bait path).
  - `attack-class` — no route, but the attack matcher recognized an injection payload (LFI/SQLi/…).
  - `suspicious` — cheap heuristics fired (cumulative anomaly from the §2.4 request-shape bot signals)
    without a specific signature. **Reserved slot**: v1 computes the signals and accrues `anomaly`, but the
    *classification* stays `clean` here until the policy owns the composite decision (S3) — the enum value
    exists so M6/S2's rule ("cumulative anomaly / a single weak signal alone → never deceive") is
    expressible. A request that fires bot signals but hits nothing else classifies `clean` with a non-zero
    `anomaly` and a populated `signals` set; the policy, not core, decides what that composite means.
- **`fakeHandle`** is the bridge to phase two: a small **pure-data** pointer (not a rendered response, not
  a bundle blob) that lets `synthesize()` deterministically rebuild the fake. Shape:
  - nuclei route: `{ kind: 'route', key: '<METHOD> <normalized-path>' }` — the resolved routing key.
  - attack class: `{ kind: 'attack', ruleId: '<id>' }` — the matched attack rule id.
  - `null` when the classification could never produce a fake (clean).
  This keeps `Verdict` serializable (it can cross the policy boundary / be cached / logged) and makes
  `synthesize()` a pure function of `(handle, profile, seed) + store`.
- **`SiteProfile` in classify:** the real-route oracle demotes a would-be probe to `clean` when the path
  is a genuine route on the host app — so a deceptive-WAF deployment (core running BEFORE the app) never
  mis-classifies a live `/wp-login.php` as a scanner bait (M2: "a fake `/wp-login.php` never collides with
  a real one"). Position-blind: the oracle is **data the caller supplies**, not core reaching into a router.

`detect()` is retained as a thin back-compat shim: `detect($r)` = `classify($r, SiteProfile::empty())
->detection`. No caller breaks.

### 2.2 `synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?FakeResponse`

Invoked **only when the caller's policy chose `deceive`** (core never decides this). Pure function of its
inputs plus the compiled store: same `(verdict, profile, seed)` → same bytes. Owns everything that
*builds* a fake and nothing that *decides* to serve one.

- Resolves `verdict.fakeHandle`:
  - `route` → re-resolve the entry's bundles from the store, apply **synthesis-integrity filtering**
    (`candidates()`: exclude deny-set, nuclei-reflection flag, severity ceiling — see §3 for where those
    knobs now live), `PersonaSelector::pick($candidates, $seed)`, then `ResponseSynthesizer::synthesize()`.
  - `attack` → `TemplateAttackEmulator` renders the named rule with `crc32($seed)`.
- Honors the **SiteProfile** at synthesis time too: if the resolved fake would collide with a declared real
  route, decline (return null) rather than shadow a live endpoint.
- Returns `null` when nothing can be safely synthesized (unsynthesizable bundle, body over the fabricated-
  content cap, collides with a real route). **Null is the contract for "degrade to the caller's 404"**
  (upholds the invariant that the engine only ever *upgrades* a 404 — a synthesis fault never escapes as a
  5xx; the caller serves its plain 404).
- **What synthesize() no longer does** (moved out to policy — §3): kill-switch, mode, trusted-bypass, the
  app suspicion `gate`, the `observer` veto/notifications, and the `usleep` serve-delay. These are WHEN/
  whether/side-effect concerns, not content construction.

> **SUPERSEDED 2026-08-25 — the `Funnypot\FakeResponse` alias was removed.** `funnypot-policy`
> defines its own real `Funnypot\Policy\FakeResponse`, so the alias left two same-named types
> either side of the boundary, one of them a `class_alias`, with nothing depending on core's copy
> but core's own test. The vocabulary argument below no longer applies: policy owns the
> policy-facing name. Core's value object is `SynthesizedResponse`, full stop. Everything else in
> this section still holds — read `FakeResponse` below as `SynthesizedResponse`.

`FakeResponse` is the existing `SynthesizedResponse` value (`status`, `headers`, `body`, `satisfies`).
The contract names it `FakeResponse` (per §M) via a class alias so the policy-facing vocabulary matches
§M while every existing use of `SynthesizedResponse` keeps compiling. `satisfies` (the served subset, for
logging) stays on the object; the *policy* reads it, not the engine.

### 2.3 `SiteProfile` — the new position-blind input

Plain value object, **data not behavior beyond one oracle closure**:

```
SiteProfile {
    declaredStack: string[]                    // e.g. ['php','nginx','wordpress'] — what the host claims to run
    routeExists:   ?callable(string $method, string $path): bool   // real-route oracle; null ⇒ "unknown, assume none"
}
static SiteProfile::empty()                    // declaredStack=[], routeExists=null — reproduces today's behavior
```

- **`routeExists`** is the collision oracle. A FALLBACK/404-position honeypot (the classic app deployment)
  passes `empty()` — there is no real app behind it, every path is fair game, behavior is unchanged. A
  BEFORE-position deceptive-WAF passes a real oracle so live routes are never shadowed.
- **`declaredStack`** lets synthesis stay coherent with the host's real fingerprint (don't fake an
  IIS/ASP.NET product on a declared nginx/PHP box). v1 may treat it as advisory; the field exists so the
  seam is reserved. It also subsumes today's `serverHeader`/`poweredBy` coherence intent.
- **Deterministic seed** is a separate scalar argument, not part of `SiteProfile`: the policy computes it
  (actor id → coherent multi-step fakes from a stateless engine, M2) and passes it into `synthesize()`.
  It replaces the engine reaching into `Config::seedFor()`.

### 2.4 Request-shape bot signals in `classify()` (decision S)

`classify()` already parses the request, so it is the natural home for the **individual** request-shape bot
signals (decision **S1**). They are cheap, position-blind, action-free **detection features**: each fires a
flag and adds a small weight to the Verdict `anomaly` score, and the whole computed set is exposed as
`Verdict.signals` (a `BotSignalSet`). Core computes and accrues; it **never decides** — the composite "is
this a bot?" judgment is the policy's (S2/S3), fused there with reputation and country. `classify()` also
adds a `bot-signal` tag to the detection when any signal fires, so the policy can cheaply see that
request-shape evidence contributed.

**Hard rules on these signals (non-negotiable):**
- **INPUT-side only → fingerprint-safe.** The signals are consumed internally (anomaly + `signals` set);
  none of the flag names, the weights, or the header fingerprint are ever *emitted* in a response, so an
  attacker can't read them back to fingerprint the honeypot (invariant #1 / project invariant #1).
- **No signal acts alone (S2 / M6).** A single missing header or one contradiction is a MODIFIER that
  raises `anomaly` — never a block/deceive on its own. `classify()` cannot block or deceive anyway
  (action-free); this just makes the weak-signal discipline explicit so no downstream reader treats a lone
  flag as decisive.
- **Position-blind.** The signals are computed the same way regardless of BEFORE/FALLBACK position; they
  are request content, not context.

**Signals computed in v1 core** (starting weights are the policy's to tune; core supplies the flags + a
default weight so `anomaly` is populated):

- **Header presence** — missing `Accept` / `Accept-Language` / `Accept-Encoding` → **+5 each**; empty (or
  absent) `User-Agent` → **+10**.
- **Fetch-metadata / client-hint absence** — missing `Sec-Fetch-Site` / `-Mode` / `-Dest` / `-User`,
  missing `Sec-CH-UA` / `-Mobile` / `-Platform`. High-signal only when the UA claims a modern browser
  (an old/legit client legitimately lacks them — see FP guard below), so these are weighted low on their
  own and lean on the self-consistency pairing.
- **Self-consistency contradictions** (a contradiction beats an absence — the sharp signals):
  - UA claims Chromium but sends no `Sec-CH-UA` and no `Sec-Fetch-*`.
  - `Accept: */*` from a browser-claiming UA (browsers send a specific `Accept` for navigations).
  - HTTP/2 request carrying a forbidden `Connection` header (h2 bans hop-by-hop `Connection`).
  - `Accept-Encoding` present but missing `gzip`.
  - UA OS vs `Sec-CH-UA-Platform` mismatch (UA says Windows, platform hint says Linux, etc.).
- **Structural header fingerprint (anti-evasion)** — a **digit-stripped, sorted-list** fingerprint: strip
  version digits from header values (`preg_replace('/\d+/', '')`) and sort list-valued headers so a
  Chromium version bump or a reordered `Accept` doesn't change the fingerprint; plus header **order + count**
  (browsers have a characteristic order/count; curl/python/Go have their own stable ones — the JA4-H idea).
  This is a *feature on the Verdict*, not an emitted value.

**Explicitly NOT computed** (S correction): **no outdated-UA / version-age detection** — fragile + high-FP.
The digit-stripping above is precisely to tolerate old-but-legit clients; presence + self-consistency +
the structural fingerprint replace version-age heuristics.

**FP guard (core's minimal share).** Core does not own the allowlist / SAFE-UA / SAFE-PATHS exemptions —
those are policy config (S5) and are applied *before* the composite decision. But because a legit
non-browser client (monitoring, API, server-to-server, feed reader) legitimately lacks browser headers,
core keeps the per-signal weights small and never lets the signal set alone change the `classification`
away from `clean`. The heavy FP work (allowlist, SAFE_PATHS, `.map` source-map exemption) is the policy's,
checked first.

**Reserved seams (NOT computed in v1 core):**
- **Edge TLS/HTTP-2 fingerprint (JA3 / JA4 / HTTP/2)** — computed at TLS/H2 termination (an nginx module /
  the edge), never inside PHP. Reserve a seam so `classify()` **consumes a fingerprint header** (e.g. a
  trusted `X-*-Fingerprint` supplied by the edge) as an extra input when present, folding it into the
  signal set. JA3-says-tool + UA-says-browser is near-certain forgery — but the compute is out of core.
- **Forged good-bot via FCrDNS** — UA claims Googlebot/Bingbot but forward-confirmed reverse-DNS doesn't
  match. Needs an rDNS lookup → an **async / enrichment-side** input, **never the request path** (classify()
  does no I/O — invariant #5 below). Reserved as a reputation/enrichment signal, not a v1 classify compute.
- **Behavioral signals** (robots.txt disobedience, spider-trap hit, honeypot-field POST, assets-never-
  fetched, no session continuity, timing/velocity) are **state-dependent → policy-side**, not stateless
  classify() features. Noted for completeness; out of this contract.

`BotSignalSet` is a **pure-data value object**: named boolean flags for each fired signal, the accumulated
weight, the UA class (`browser | script | scanner | empty | unknown`), and the digit-stripped structural
fingerprint string. It is serializable so it rides on the Verdict across the policy boundary, can be cached
or logged by the *policy*, and — per decision **T** — can travel to mainnet as the opt-in `signals`
telemetry payload (T5) that the thin adapter forwards on `check`/`report`. Core only computes and exposes
it; core never transmits it (no I/O).

---

## 3. Concern re-partition (this is the whole refactor, in one table)

Everything in today's `respond()`/`Config` lands on exactly one side of the classify/synthesize line, or
moves up to the policy. Position-blind + action-free means **all WHEN/whether/side-effect logic leaves core.**

| Today (in `respond()` / `Config` / `Observer`)        | Two-phase home                                             |
|---|---|
| `killSwitch`, `mode`/`respondEnabled`, `trustedBypass`| **funnypot-policy** (the caller decides WHEN to call synthesize) |
| `gate` (app suspicion predicate)                      | **funnypot-policy** (its decision matrix)                  |
| `observer->onDetection/shouldRespond/onOutcome`       | **funnypot-policy** (logging/scoring/veto/reporting)       |
| `serveDelayMicros()` / `latencyMs` / `latencyJitterMs`| **funnypot-policy** or host action layer (a tarpit is an ACTION; M3 even cut tarpit from v1) |
| `probeSignature` / sig=1 root guard                   | **classify()** — a bare-root hit without a probe signature classifies `clean` |
| route resolution + `detectionFor` + attack **match**  | **classify()**                                             |
| request-shape **bot signals** (S1: header presence, fetch-metadata/client-hint absence, self-consistency, digit-stripped structural fingerprint) | **classify()** — computed as anomaly-contributing features + the `signals` set; the **composite** bot decision is **funnypot-policy** (S2/S3) |
| `candidates()` (exclude / nucleiReflection / severity ceiling) | **synthesize()** — synthesis-integrity: which persona this site may present |
| `PersonaSelector::pick(seed)`                          | **synthesize()** — needs the seed; a determinism concern   |
| `ResponseSynthesizer` (+ STYLE) / `TemplateAttackEmulator` render | **synthesize()** — the retained deception content   |
| `maxBodyBytes` fabricated-content cap                 | **synthesize()** — a safety bound on what it builds         |
| `responseStyle`, `serverHeader`, `poweredBy`, `exclude`, `nucleiReflection`, `severityCeiling` | a **`SynthesisConfig`** the engine holds (the synthesize-only remainder of today's `Config`) |
| `personaSeed` / `seedSalt`                            | the **caller** computes the seed and passes it in           |

Net: `Config` splits into a **`SynthesisConfig`** (the synthesize-only knobs, held by the engine) and a
pile of policy closures that **leave core entirely**. The engine constructor stops taking `gate`,
`killSwitch`, `trustedBypass`, `mode`, `probeSignature`, `latency*`, and the `Observer`.

---

## 4. `EvaluatorInterface` — how core plugs into `funnypot-policy`

`funnypot-policy` (decision M3) holds the engine behind an `EvaluatorInterface` and *decides when to call
classify/synthesize*. The port (defined in the policy package; core depends on the package and implements
it) is shaped to the two-phase contract:

```
interface EvaluatorInterface {
    classify(RequestContext $r, SiteProfile $profile): Verdict;
    synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?FakeResponse;
}
```

`Funnypot\Honeypot` implements it directly — the method names and signatures above **are** the interface.
The policy's cheapest-first matrix (allowlist → local pin → cheap-static → reputation → **engine
classify()**, M5) calls `classify()` *last* (it is the expensive content gate) and calls `synthesize()`
*only* on a `deceive` decision. Core neither knows nor cares about the earlier gates.

**Dependency direction / phasing note:** the interface lives in `funnypot-policy`, but core must not take a
hard build dependency on a package that consumes it in a way that inverts the graph. Resolution: core
defines the two-phase **methods** natively (they exist regardless of any package); `funnypot-policy`
declares `EvaluatorInterface` with the identical shape and core adds `implements EvaluatorInterface`
via a `composer require` on the policy package's `-contracts` slice (or the policy package depends on core
and the interface is structurally satisfied). The plan sequences this so the suite never goes red; the
concrete wiring choice is a plan decision, the contract shape is fixed here.

---

## 5. The four position×action combos this enables (validation, not new code)

The split is what lets one core+policy serve all of M4's combos without a code change — the operator picks
posture/position/action as **config**, and core stays identical:

- **deceive-AFTER** (classic honeypot): FALLBACK position, `SiteProfile::empty()`, policy calls
  synthesize on the 404 fallback. This is today's behavior, preserved byte-for-byte.
- **deceive-BEFORE** (deceptive WAF): BEFORE position, real `routeExists` oracle so live routes pass
  through untouched; policy synthesizes on the sacrificial-path / high-certainty set.
- **block-BEFORE** (classic WAF): policy returns `block` from its matrix; **synthesize() is never
  called** — core did classify() only.
- **block-AFTER** (rare): same, at the fallback position.

Core does classify() always (cheap) and synthesize() only on deceive. It cannot tell which combo it is in —
that is the point.

---

## 6. Invariants this design must not break

1. **Fingerprint-safety** (project invariant #1 / ARCHITECTURE): no canonical scanner/matcher signature
   strings emitted or added to any artifact. The CI gate (`scripts/ci/check-fingerprint-safety.php`) must
   stay green — the refactor moves code, it must not surface a nuclei matcher word or CRS `msg`/id into a
   new type name, log field, or `Verdict`/`FakeHandle` value. The §2.4 **bot signals are INPUT-side only**:
   the flag names, weights, and digit-stripped fingerprint live on `Verdict.signals` for the policy to read
   and (per T) forward as telemetry, but **core never emits them in a response** — no signal name or
   fingerprint value may reach a `FakeResponse` header/body, or an attacker reads the honeypot's own
   detection logic back off the wire.
2. **The engine only ever *upgrades* a 404** (project invariant #2): `synthesize()` returning `null` is
   the sole "no fake" signal; any internal fault degrades to `null`, never an exception that could surface
   as a 5xx. Position-blindness reinforces this — core never emits a status the policy did not ask for.
3. **Content-Type matches the request; status is app/policy-chosen** (project invariant #5): unchanged —
   `FakeResponse.status` is chosen by the synthesis content, and the policy owns the final action status;
   no model/engine-driven 3xx.
4. **7.3-clean** (decision C): all new types (`Verdict`, `SiteProfile`, `FakeHandle`, `SynthesisConfig`)
   and the split methods are authored to the PHP 7.3 floor — **no** constructor promotion, class-level
   typed properties, arrow functions, or `??=`. Classic constructors + docblocked properties, matching
   what piece C down-levels the rest of core to. Piece C's conversion surface must include these new files.
5. **Deterministic + side-effect-free core** (existing guarantee): `classify()` and `synthesize()` do no
   I/O, no logging, no delay, no scoring. `synthesize()` is a pure function of `(verdict, profile, seed,
   store)`. This is what makes the engine testable, cacheable, and position-blind.
6. **No behavior change for the existing app** during the refactor: `respond()` survives as a **facade**
   over classify()+synthesize() with the old `Config` gates layered back on, so the app's
   `HoneypotController` and the whole existing suite (incl. the nuclei acceptance run) stay green until the
   app migrates to the policy on its own schedule.

---

## 7. Types added / changed (summary for the plan)

**New** (`src/` — 7.3-clean value types):
- `Funnypot\Verdict` — classification enum-const + `Detection` + severity + anomaly + `BotSignalSet` +
  `?FakeHandle`.
- `Funnypot\BotSignalSet` — pure-data request-shape signal set (decision S): named boolean flags
  (header-presence, fetch-metadata/client-hint absence, self-consistency contradictions), accumulated
  weight, UA class, and the digit-stripped/sorted-list structural fingerprint string. Serializable
  (rides the Verdict; travels as the decision-T `signals` telemetry). INPUT-side only — never emitted.
- `Funnypot\FakeHandle` — `{ kind, key?, ruleId? }` opaque synthesize pointer.
- `Funnypot\SiteProfile` — `declaredStack[]` + `?routeExists` oracle + `::empty()`.
- `Funnypot\SynthesisConfig` — the synthesize-only remainder of `Config` (style, ceiling, exclude,
  nucleiReflection, maxBodyBytes, serverHeader, poweredBy).
- ~~`Funnypot\FakeResponse` — class alias of `SynthesizedResponse`~~ — **removed 2026-08-25**; use `SynthesizedResponse`.
- `EvaluatorInterface` — defined in `funnypot-policy`; `Honeypot` implements it (see §4 phasing).

**Changed:**
- `Funnypot\Honeypot` — gains `classify()` + `synthesize()`; `respond()` becomes a thin facade; `detect()`
  delegates to `classify()`; constructor sheds the policy closures/observer (kept on a deprecated overload
  during migration).
- `Funnypot\Engine` interface — gains the two methods; `respond()`/`detect()` retained, marked legacy.
- `Funnypot\Config` — synthesize knobs migrate to `SynthesisConfig`; policy closures deprecated. (Kept
  intact behind the facade until the app migrates — the plan removes it last, or leaves it as a
  facade-builder.)

**Untouched** (the retained deception content): `Synthesis\ResponseSynthesizer`, `Response\*` emulators,
`Template\TemplateAttackEmulator`, `Support\PersonaSelector`, the compiled artifacts and the store. The
refactor **re-homes call sites; it does not rewrite the synthesizers.**

---

## 8. Open questions for the plan (not blockers)

- **`EvaluatorInterface` package boundary** — does core `require` a `funnypot-policy` contracts slice, or
  does the policy package depend on core and satisfy the interface structurally? Pick the direction that
  keeps composer acyclic and the 7.3 lane bootable (BL1). Decided in the plan; contract shape is fixed.
- **`anomaly`/`suspicious` in v1** — resolved by decision S: classify() v1 **does** compute the §2.4
  request-shape bot signals (they are cheap — it already parses the request) and accrues `anomaly` + the
  `signals` set, but still returns `clean|scanner-probe|attack-class` and reserves the `suspicious`
  *classification* for the policy's composite decision (S2/S3). Core computes signals; core never classifies
  a bare anomaly as `suspicious`.
- **Edge fingerprint header ingestion** — the JA3/JA4/HTTP-2 seam (§2.4 reserved): confirm in the plan the
  trusted-header name/shape classify() would consume if the edge supplies one; not a v1 compute, just the
  input seam.
- **LLM-as-synthesizer wiring** — the follow-up to fold the app's `LlmFakeResponder` behind a
  `FakeHandle{kind:'llm'}` the policy can name; out of v1 core scope, tracked as a ripple.

---

## Review resolutions applied (2026-08-19)

### S/T signals+telemetry

Decisions **S** (request-shape bot signals) and **T** (signals ride check + report; check as low-trust
telemetry) from `funnypot-mainnet/docs/2026-08-19-program-decisions.md`, applied to the funnypot-core
half:

- **S1 — individual signals in `classify()`.** `classify()` computes the request-shape bot signals as
  anomaly-contributing detection features: header-presence (missing `Accept`/`Accept-Language`/
  `Accept-Encoding` +5 each; empty `User-Agent` +10), fetch-metadata/client-hint absence, self-consistency
  contradictions, and the digit-stripped/sorted-list structural header fingerprint (§2.4). Added `signals:
  BotSignalSet` to the Verdict (§2.1) and a new `Funnypot\BotSignalSet` value type (§7); `anomaly` now folds
  the signal weights; a `bot-signal` detection tag fires when any signal is present.
- **S2 / M6 — no weak signal acts alone.** Documented as a hard rule (§2.4): each signal is a MODIFIER that
  raises `anomaly`; core is action-free and never classifies a bare anomaly as `suspicious` — the composite
  decision is the policy's (S3), out of this contract.
- **Fingerprint-safety (invariant #1).** The signals are INPUT-side only — computed and exposed on the
  Verdict, **never emitted** in a `FakeResponse`. Reinforced in §6.1.
- **Reserved seams (not v1 core compute).** Edge JA3/JA4/HTTP-2 fingerprint consumed as a trusted request
  header if present; FCrDNS forged-good-bot as an async/enrichment input, never the request path; behavioral
  signals as policy-side, state-dependent (§2.4 reserved seams; §8 open question on the header shape).
- **NOT computed.** No outdated-UA / version-age detection (fragile + high-FP); the digit-stripping exists
  precisely to tolerate old-but-legit clients (§2.4).
- **T — telemetry seam.** `BotSignalSet` is serializable so it rides the Verdict and the thin adapter can
  forward it as decision-T `signals` telemetry on `check`/`report`. Core only computes and exposes; it
  performs no I/O and never transmits (§2.4, §6.5) — the async, opt-in, low-trust handling of T is the
  adapter's / mainnet's, out of core scope.
