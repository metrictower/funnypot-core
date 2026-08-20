# funnypot-core · two-phase engine contract — implementation plan

**Status:** draft for build · **Date:** 2026-08-19 · **Piece:** funnypot-core half of decision **M**.
**Implements:** `docs/2026-08-19-two-phase-engine-contract-design.md` (the design is the source of truth;
this plan executes it and does not redesign it). **Aligns with** §M of
`funnypot-mainnet/docs/2026-08-19-program-decisions.md`.

A **disciplined, test-driven** refactor. The organizing principle: the split lands **behind the existing
`respond()` as a facade first**, so the whole current suite (plus the nuclei acceptance run) stays green at
every phase; only after classify()+synthesize() are proven equivalent do callers migrate off `respond()`.
No compiled-artifact change, no synthesizer rewrite — call sites are re-homed, the deception content is
moved wholesale.

---

## Orientation & constraints

- **Repo:** `/Users/bobmaher/myrepos/funnypot-project/funnypot-core`, branch `main` (project git workflow).
  Framework-free, `Funnypot\ → src/`, `Funnypot\Tests\ → tests/`.
- **Sequencing vs piece C (7.3 down-level):** every new file is authored **7.3-clean from birth** (design
  §6.4 — no promotion / typed props / arrow fns / `??=`). Coordinate with C so its conversion inventory
  **includes these new files** rather than re-converting them; if C lands first, match its converted style.
- **Green baseline (D9, run-and-compare):** Phase 0 records `php vendor/bin/phpunit` on the host
  (tests/assertions) and every later phase compares against **that recorded number**, never a literal.
- **Acceptance:** the real-nuclei `tests/acceptance/run.sh` corpus is the golden master for
  synthesize()-equivalence — the strongest regression signal that a moved synthesizer still produces
  scanner-satisfying bytes.
- **Fingerprint-safety gate** (`scripts/ci/check-fingerprint-safety.php`) must pass after every phase that
  adds a type/field — no matcher word may leak into a `Verdict`/`FakeHandle`/log name.

---

## Phase 0 — baseline & scaffolding (no behavior change)

- Record the green baseline (tests/assertions) on the host; note it in the PR description.
- Add the **pure value types** with tests, wired to nothing yet:
  - `SiteProfile` (`declaredStack[]`, `?routeExists`, `::empty()`), `FakeHandle` (`kind`/`key`/`ruleId`),
    `BotSignalSet` (named boolean flags, accumulated weight, UA class, digit-stripped structural
    fingerprint — decision S / design §2.4), `Verdict` (classification const-strings, `Detection`, severity,
    anomaly, `BotSignalSet`, `?FakeHandle`),
    `SynthesisConfig` (style/ceiling/exclude/nucleiReflection/maxBodyBytes/serverHeader/poweredBy).
  - `FakeResponse` class alias of `SynthesizedResponse`.
- Unit tests: construction, defaults, `SiteProfile::empty()` semantics, classification-enum validity,
  `FakeHandle` round-trips as pure data, `BotSignalSet` is empty/zero-weight by default and round-trips
  as pure serializable data (it must survive crossing the policy boundary + become T telemetry).
  **Suite green at the recorded baseline + new tests.**
- **Gate:** fingerprint-safety green; `php -l` on the host; the files parse under the 7.3 lane (BL1 env:
  `pdo_sqlite`+`curl`+`sodium`, per C).

**Exit:** the vocabulary exists and is tested; `Honeypot` unchanged.

## Phase 1 — extract `classify()` (detection widened; behavior parity)

- **TDD:** write `classify()` tests first from `detect()`'s current behavior — for every existing
  `detect()` fixture, `classify($r, SiteProfile::empty())->detection` must equal today's `detect($r)`.
- Implement `classify()`:
  - route resolution + `detectionFor()` (lifted from `detect()`), producing `scanner-probe` +
    `fakeHandle{kind:'route', key}`.
  - on a route miss, run the **attack matcher's match half** (from `TemplateAttackEmulator`, without
    rendering — see Phase 2 note on sharing the match) → `attack-class` + `fakeHandle{kind:'attack',
    ruleId}`. If the matcher must render to know it matched, Phase 1 may call `emulate()` and discard the
    body (correctness first); Phase 2 factors a render-free `match()` if the throwaway is measurable.
  - sig=1 root without probe-signature → `clean` (fold today's `hasProbeSignature` guard into classify;
    the predicate becomes a classify input, not a Config closure).
  - consult `SiteProfile.routeExists`: a hit on a declared real route → `clean` (never shadow a live route).
- Re-point `detect()` to delegate: `detect($r)` = `classify($r, SiteProfile::empty())->detection`.
- **Suite green** (detect() callers unaffected); add classify-specific tests (attack-class classification,
  real-route demotion, sig=1 clean).

**Exit:** classify() is the single detection path; `respond()` still fused but can now read a `Verdict`.

## Phase 1b — request-shape bot signals in `classify()` (decision S / design §2.4)

Additive detection features on top of the extracted `classify()`. **Pure computation, no I/O, no action** —
each signal fires a `BotSignalSet` flag + adds a weight to `Verdict.anomaly`; a `bot-signal` detection tag
fires when any signal is present. Sequenced after Phase 1 so it rides the proven classify() path; it does
**not** change any Phase-1 `detection` equivalence (bot signals are orthogonal to route/attack matching).

- **TDD, signal by signal:**
  - **Header presence** — missing `Accept`/`Accept-Language`/`Accept-Encoding` → +5 each; empty/absent
    `User-Agent` → +10. Tests assert exact weight accrual and the fired flags.
  - **Fetch-metadata / client-hint absence** — missing `Sec-Fetch-Site|Mode|Dest|User`,
    `Sec-CH-UA|-Mobile|-Platform`. Low weight alone; tests pair them with a browser-claiming UA.
  - **Self-consistency contradictions** — UA claims Chromium but no `Sec-CH-UA`/`Sec-Fetch-*`; `Accept: */*`
    from a browser UA; HTTP/2 request with a forbidden `Connection` header; `Accept-Encoding` present but
    missing `gzip`; UA-OS vs `Sec-CH-UA-Platform` mismatch. One test per contradiction (a contradiction
    beats an absence).
  - **Structural fingerprint** — digit-stripped (`preg_replace('/\d+/','')`) + sorted-list header
    fingerprint + header order/count. Tests: a Chromium version bump and a reordered list-header produce the
    **same** fingerprint (anti-evasion); curl/python/Go produce distinct stable ones.
- **NOT implemented** (S correction): no outdated-UA / version-age detection. A test asserts an old-but-legit
  UA is not penalised on version age alone.
- **FP-guard boundary:** core keeps per-signal weights small and **never** lets the signal set alone move
  `classification` off `clean`; the allowlist / SAFE-UA / SAFE-PATHS / `.map` exemptions are the policy's
  (S5), not core's. A test asserts a request that fires only bot signals classifies `clean` with non-zero
  `anomaly` + a populated `signals` set (the composite call is the policy's, S2/S3).
- **Fingerprint-safety gate** must stay green — a test/assertion confirms no signal flag name or fingerprint
  value can reach a `FakeResponse`; the signals are INPUT-side only.
- **Reserved seams (design only, not built):** the edge JA3/JA4/HTTP-2 trusted-header input and the FCrDNS
  async good-bot check are documented as future inputs; no v1 compute, no test beyond asserting the seam is
  absent from the request path.

**Exit:** `classify()` populates `Verdict.signals` + `anomaly` from the request-shape signals; the composite
bot decision remains the policy's; fingerprint-safety green.

## Phase 2 — extract `synthesize()` (the retained deception content)

- **Golden-master first:** capture `respond()` output (status/headers/body) across the full acceptance
  corpus + unit fixtures as the equivalence oracle for this phase.
- Implement `synthesize(Verdict, SiteProfile, string $seed): ?FakeResponse`:
  - `route` handle → re-resolve bundles, apply `candidates()` (exclude / nucleiReflection / severity
    ceiling — now read from `SynthesisConfig`), `PersonaSelector::pick($candidates, $seed)`,
    `ResponseSynthesizer::synthesize()`, `maxBodyBytes` cap. Real-route collision → null.
  - `attack` handle → `TemplateAttackEmulator` render of the named rule with `crc32($seed)`, severity
    ceiling + size cap.
  - any unsynthesizable/over-cap/collision → `return null` (the "degrade to 404" contract).
- **Re-implement `respond()` as a facade** over classify()+synthesize(): it computes the `Verdict`,
  applies the **old Config gates in place** (killSwitch, mode, trusted, gate, observer onDetection /
  shouldRespond veto / onOutcome, serveDelay), derives the seed via `Config::seedFor()`, and calls
  `synthesize()` for the content. `tryAttack()` collapses into "classify returned attack-class → synthesize".
- **Suite green + acceptance byte-identical.** The facade guarantees every existing `respond()` test and
  the app's `HoneypotController` see unchanged behavior.

**Exit:** classify()+synthesize() are the real engine; `respond()` is a compatibility shell.

## Phase 3 — `SiteProfile` + explicit seed as first-class inputs

- Thread `SiteProfile` through the public methods (already in signatures from Phase 1–2); add tests for
  the BEFORE-position case: a real `routeExists` oracle makes classify() return `clean` for live routes
  and synthesize() decline collisions, while `::empty()` reproduces today's FALLBACK behavior exactly.
- Make the **seed an explicit `synthesize()` argument** end-to-end; the facade keeps deriving it from
  `Config::seedFor()` so nothing external changes yet.
- Tests: determinism (`synthesize` byte-stable for fixed `(handle, profile, seed)`), and per-seed persona
  spread unchanged from today.

**Exit:** position-blindness is demonstrable via `SiteProfile`; the engine is a pure two-phase function.

## Phase 4 — `EvaluatorInterface` + `Engine` contract update

- Add the two methods to `Funnypot\Engine`; mark `respond()`/`detect()` **legacy** (kept, documented as
  the facade). `Honeypot implements EvaluatorInterface` (from `funnypot-policy`) — resolve the package
  boundary per design §4/§8 so composer stays acyclic and the 7.3 lane still boots (BL1). If
  `funnypot-policy` is not yet buildable, land the interface shape in core under a clearly-marked
  `Contracts\Evaluator` and re-alias when the package exists — **do not block core on the sibling package.**
- Split `Config`: move the synthesize knobs into `SynthesisConfig` (the engine holds it); leave the policy
  closures on a **deprecated `Config`** that the facade still accepts. Add a 7.3-callable array/builder
  factory for the config objects (M15 — no named args on 7.3), with a `ConfigFactoryTest`.
- **Suite green;** the recorded baseline shifts by the new factory/interface tests (expected, per D9).

**Exit:** core presents the position-blind, action-free `EvaluatorInterface`; `respond()` remains for the
unmigrated app.

## Phase 5 — hardening, gates, docs

- Confirm **7.3-clean** across all new/changed files (run the C 7.3 lane); confirm **fingerprint-safety**
  and **license** gates green; `php -l` clean.
- Update `docs/INTEGRATION.md` with the two-phase contract and the `SiteProfile`/seed inputs; add a short
  note that `respond()` is the legacy facade and new consumers use classify()/synthesize() via
  `funnypot-policy`.
- Leave the app migration (`HoneypotController` → policy) to the D/E adapter workstream (below); core is
  done when the facade + the two-phase methods coexist green.

**Exit:** the engine is split, position-blind, action-free, 7.3-clean, all gates green, deception retained.

---

## Ripples to hand off (not built here)

- **`funnypot-policy` (new piece, decision M3):** owns `EvaluatorInterface`, the cheapest-first matrix,
  learn-then-enforce, pin/TTL, and the report-suppression layer — its own spec+plan. This plan only fixes
  the interface *shape* core implements.
- **App (`funnypot`) / D / E adapters:** migrate `HoneypotController::handle()` off `Config(mode:respond,
  gate:fn()=>true)`+`respond()` onto a policy that calls classify()/synthesize(); the observer's
  logging/scoring/AbuseIPDB-report and the `serveDelay` move into the policy/host action layer; the
  app-side `LlmFakeResponder` is registered as a `FakeHandle{kind:'llm'}` synthesizer (design §1 tension /
  §8). Until then, the `respond()` facade keeps the app working untouched.
- **Piece C (7.3):** add the new files to C's conversion inventory (or author them post-C in the converted
  style); the new `SynthesisConfig`/factory tests shift C's run-and-compare baseline (expected).

---

## Test strategy (summary)

- **Equivalence oracles:** Phase 1 pins classify() to `detect()`; Phase 2 pins synthesize()+facade to a
  captured golden master of `respond()` + the real-nuclei acceptance corpus (byte-identical).
- **New unit tests:** value-type construction; classification mapping (clean/scanner-probe/attack-class,
  reserved suspicious); `SiteProfile` real-route demotion (classify) and collision decline (synthesize);
  synthesize determinism for fixed `(handle, profile, seed)`; the config factory (M15).
- **Bot-signal tests (Phase 1b, decision S):** per-signal weight accrual + fired flags (header presence,
  fetch-metadata/client-hint absence, each self-consistency contradiction); the digit-stripped/sorted-list
  fingerprint is stable across a version bump / list reorder and distinct per client class; an old-but-legit
  UA is not penalised on version age; a signals-only request stays `clean` with non-zero `anomaly` +
  populated `signals`; `BotSignalSet` round-trips as pure serializable data (T telemetry); a fingerprint-
  safety assertion that no signal name/fingerprint reaches a `FakeResponse`.
- **Every phase** ends green at the recorded baseline (+ that phase's new tests) on the host, with
  fingerprint-safety + license gates passing and the 7.3 lane parsing the new files.

---

## Review resolutions applied (2026-08-19)

### S/T signals+telemetry

Decisions **S** and **T** (`funnypot-mainnet/docs/2026-08-19-program-decisions.md`), applied to this plan
consistently with the design's §2.4 / §7 / changelog:

- **Phase 0** adds the `BotSignalSet` pure value type (flags + weight + UA class + digit-stripped
  fingerprint) with round-trip/serialization tests; `Verdict` gains the `signals` field.
- **New Phase 1b** computes the request-shape bot signals in `classify()` (header presence, fetch-metadata/
  client-hint absence, self-consistency contradictions, digit-stripped/sorted structural fingerprint) as
  anomaly-contributing features — TDD signal by signal, no I/O, no action.
- **Test strategy** gains the bot-signal cases: weight accrual, fingerprint stability/anti-evasion, the
  old-but-legit-UA non-penalty, the signals-only-stays-`clean` guarantee, and the fingerprint-safety
  assertion that no signal name/fingerprint reaches a `FakeResponse`.
- **Out of core scope (design §2.4/§8):** the composite bot decision (funnypot-policy, S2/S3); the edge
  JA3/JA4/HTTP-2 header ingestion and FCrDNS async good-bot seams (reserved, not built); the decision-T
  async/opt-in forwarding of the `signals` telemetry on check/report (the thin adapter + mainnet). Core
  computes and exposes; it never transmits.
