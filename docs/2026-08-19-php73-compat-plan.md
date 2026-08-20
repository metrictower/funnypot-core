# funnypot-core · Piece C (core-php73) — implementation plan

**Status:** draft for build · **Date:** 2026-08-19 · **Piece:** C of the funnypot-mainnet program
**Implements:** `docs/2026-08-19-php73-compat-design.md` (the design is the source of truth; this plan
executes it and does not redesign it).

This is a **disciplined, test-driven** plan for a *mechanical* down-level: lower the language floor of
`metrictower/funnypot-core` from PHP 8.0 to PHP 7.3 with **zero behaviour, API, or compiled-artifact
change**. Every phase is a small, independently verifiable increment; the whole suite stays green on
the host PHP throughout, while a real-7.3 interpreter goes progressively green as constructs convert.

---

## Orientation

### What exists now (grounded, 2026-08-19)

- **Repo:** `/Users/bobmaher/myrepos/funnypot-project/funnypot-core` — framework-free PHP library,
  `Funnypot\` → `src/`, `Funnypot\Tests\` → `tests/`. Work on branch `main` (per project git workflow).
- **composer.json:** `"require": { "php": ">=8.0" }`. Dev deps: PHPUnit `^9.5`, nyholm/psr7 `^1.8`,
  psr/http-* interfaces, and **symfony/yaml `^5.4 || ^6.0`**. PHPUnit 9, nyholm/psr7, and the psr/*
  interfaces are 7.3-compatible. **symfony/yaml is NOT, as locked (BL1):** the `^5.4 || ^6.0` constraint
  and the committed `composer.lock` resolve the 6.x arm — **v6.4.43**, whose own `"php": ">=8.1"` cannot
  install or parse on 7.3. This must be narrowed to `"symfony/yaml": "^5.4"` and the lock regenerated
  (Phase 7); until then the 7.3/7.4 CI lanes cannot boot phpunit. `ext-sodium`/`ext-openssl` are runtime
  `suggest` extensions, untouched. **There is no runtime `require` today; C adds one — `metrictower/mainnet-client`
  (F, Phase 7)** — the new home of Piece B's relocated reporter, a PHP `>=7.3` package core re-exports.
- **Baseline (captured dynamically, D9):** `php vendor/bin/phpunit` on host **PHP 8.4.10** /
  **PHPUnit 9.6.36** was green at **327 tests / 4190 assertions** at the time of writing, but the plan
  does **not** hardcode that pair. The new `ConfigFactoryTest` (M15, Phase 3) shifts the totals, so
  Phase 0 **records** whatever the host reports and every later phase compares against **that recorded
  baseline** (run-and-compare), not a literal 327/4190. The green baseline (at its recorded count) must
  hold on the host at every phase. (Under F, Piece B's reporter no longer lands `src/Report/` tests in
  core — it relocates to `metrictower/mainnet-client` — so those conditional tests are not part of
  core's count.)
- **Test config:** `phpunit.xml.dist` (bootstrap `tests/bootstrap.php`, suite = whole `tests/` dir).
  28 `*Test.php` files.
- **CI:** `.github/workflows/tests.yml` — a `phpunit` job over matrix `['8.0','8.1','8.2','8.3','8.4']`,
  plus an `acceptance` job (PHP 8.3) running real nuclei via `tests/acceptance/run.sh`.
- **Gates:** `scripts/ci/check-fingerprint-safety.php` (scans the compiled artifact for detector
  signatures — runtime-version-independent), `scripts/ci/check-license.sh`. Neither is wired into
  `tests.yml` today (they run in the `update-*`/`publish-*` workflows).

### The exact conversion surface (grepped, matches design §4.1)

| Construct | Introduced | Real sites | Where |
|---|---|---|---|
| Constructor property promotion | 8.0 | 94 params across **19** files | DTOs + engine (see §Phase list) |
| Class-level typed properties | 7.4 | 101 standalone decls across 24 files | heaviest: `Compiler/Bundle`, `Compiler/Matcher/MatcherResult`, `Rules/RulesUpdater`, `Rules/RulesStatus`, `Rules/UpdateResult` |
| Arrow functions `fn()` | 7.4 | **15** in `src/` + **22** in `tests/` | 12 src files (the 6 extra grep hits in `Config.php` are docblock comments, not code) |
| `??=` | 7.4 | **1** | `src/Compiler/Crs/CrsCompiler.php:72` |

Everything else an 8.x audit would look for (`match`, `enum`, `?->`, named args, union/`mixed` types,
`readonly`, attributes, `str_contains`, …) is **already absent** (design §4.1). **The whole job is
four constructs.** Confirmed arrow-fn code sites (from grep):
`Detection.php:47`, `Response/RouteTemplateEmulator.php:109`, `Rules/RulesUpdater.php:238`,
`Compiler/TemplateLoader.php:81,82`, `Compiler/Classifier.php:187`,
`Compiler/Matcher/DslInverter.php:45,378`, `Compiler/Crs/CrsCompiler.php:200`,
`Compiler/Matcher/RegexWitnessGenerator.php:57`, `Compiler/Matcher/WordMatcherInverter.php:53,112`,
`Compiler/Crs/RegexAggregator.php:94`, `Compiler/Crs/CrsRuleParser.php:210`,
`Compiler/Crs/CrsArchetypes.php:130`.

### How to run the tests for this repo

- **Host (PHP 8.4), the standing dev loop:** `php vendor/bin/phpunit` (from repo root). Must stay green
  every phase — 8.4 runs the down-levelled forms fine.
- **Real PHP 7.3 (the driving signal):** the host linter is 8.4 and *accepts* 7.4/8.0 syntax, so it
  **cannot** detect a 7.3 violation. A genuine 7.3 interpreter is mandatory. Use Docker.
  **The 7.3 (and 7.4) verification container must carry `sodium`** so the rules trust-chain's
  extension-conditional tests actually **run** rather than skip; a skipped test silently shifts the
  count and defeats the run-and-compare baseline. (D9 also asked for `pdo_sqlite` + `curl` to cover
  Piece B's `src/Report/` tests; under **F** those tests relocate to `metrictower/mainnet-client` and
  are no longer in core's suite, so `sodium` is the extension core's own 7.3 container actually needs —
  `pdo_sqlite`/`curl` stay harmless to include.) Build a one-off `php:7.3-cli` image with `sodium` in
  Phase 1 and reuse it for all 7.3 runs (the stock image lacks it). Commands below assume that image:
  ```bash
  # one-time: pull the image
  docker pull php:7.3-cli
  # parse-check sweep on 7.3 (per-file, fatal-per-file — measures progress by count of clean files)
  docker run --rm -v "$PWD":/app -w /app php:7.3-cli \
    sh -c "find src tests -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null"
  # full suite on 7.3 (deps already vendored; PHPUnit 9.6 runs on 7.3)
  docker run --rm -v "$PWD":/app -w /app php:7.3-cli php vendor/bin/phpunit
  # a single test class on 7.3 (for incremental cluster verification)
  docker run --rm -v "$PWD":/app -w /app php:7.3-cli \
    php vendor/bin/phpunit --filter <TestClassName>
  ```
  Note: `php -l` is **per-file fatal** — a converted leaf file lints clean even while others still fail,
  so the shrinking parse-error set is the progress meter. A *targeted* 7.3 phpunit run only works once
  the target's whole autoload closure is converted — hence the leaf-first ordering below.

### TDD framing for a mechanical down-level

There is no new behaviour to test, so the "test written first" is the **7.3 verification harness itself**:
Phase 1 lands the executable 7.3 parse-check and the failing 7.3 CI lane *first* (RED — the whole
inventory fails to parse on 7.3). Every conversion phase then drives a well-defined subset of that RED
to GREEN, while the pre-existing suite (unchanged, at its Phase-0 recorded count) is the
behaviour-equivalence oracle: if a conversion altered behaviour, an existing test breaks. We add **no**
new behavioural assertions; we add the 7.3 lane, a parse-check, and an anti-regression lint. The
equivalence check is **run-and-compare against the Phase-0 baseline**, not a hardcoded 327/4190 (D9).

---

## Phase 0 — Baseline capture & 7.3 harness (RED reproduced)

**Change:** none to source. Establish the two reference points.

**Test first / verify:**
1. Host baseline (**dynamic capture, D9**): `php vendor/bin/phpunit` → green. **Record the exact
   tests/assertions pair the run reports** into the phase log (at time of writing 327/4190, but the
   recorded value — not that literal — is the oracle every later phase compares to via run-and-compare).
   Under **F** there is no `src/Report/` tree in core (B's reporter relocates to
   `metrictower/mainnet-client`), so the count moves only for the new `ConfigFactoryTest` (M15, Phase 3).
2. Pull `php:7.3-cli`; run the parse-check sweep (command above) → **it fails** on the promotion/
   typed-prop/arrow-fn files. Capture the failing-file list; confirm it matches the design §4.1 inventory
   (19 promotion files + typed-prop files + 12 arrow-fn files + `CrsCompiler.php`). Under **F** there is
   **no `src/Report/*`** to include — B's reporter lives in `metrictower/mainnet-client`, not core.

**Done-criteria:** host suite green at the **recorded** baseline count; 7.3 parse sweep reproduces the
expected failures and the failing set equals the documented surface (the four constructs, across the src
tree — **no `src/Report/`** under F). If any file fails 7.3 for a construct *not* in the four, stop and
escalate (design assumed exhaustive inventory).

---

## Phase 1 — 7.3 verification gates as executable tests (test infra, RED)

**Change (test/infra only, no `src` edits):**
- Add `scripts/ci/parse-check.sh`: `find src tests -name '*.php' -print0 | xargs -0 -n1 php -l`
  (exit non-zero on any parse failure). This is the cheap tripwire that runs before phpunit boots.
- Add `scripts/ci/anti-regression-lint.sh` (design §7): grep-fail if any of the four converted
  constructs reappear — arrow-fn code (`\bfn\s*\(` in `src`/`tests`, excluding docblock lines),
  `??=`, promotion modifiers (`(public|private|protected)\b` inside a `__construct(` signature),
  and class-level typed props. **The typed-prop type token must be broad (nit):** match FQCN/namespaced
  (`Rules\KeyRing`), nullable (`?Type`), and union (`A|B`) tokens, not just `\w+` — e.g. a type token
  like `\??[\w\\]+(\s*\|\s*[\w\\]+)*` rather than `\??\w+`, so `private Rules\KeyRing $x;` is caught.
  Add a **namespaced-type fixture** to the lint's self-test so this forward-guard stays covered even
  though zero such properties exist today. Tune the regexes against the current tree so they report
  **only** the known sites now and **zero** after conversion — that inversion is the lint's own self-test.
- Edit `.github/workflows/tests.yml`:
  - extend the `phpunit` matrix to `['7.3','7.4','8.0','8.1','8.2','8.3','8.4']`;
  - add a step (before phpunit) running `bash scripts/ci/parse-check.sh`;
  - add a step running `bash scripts/ci/anti-regression-lint.sh`;
  - add a step running `php scripts/ci/check-fingerprint-safety.php` on at least the 7.3 lane
    (Invariant #1 — this gate scans a committed **static artifact** and is version-independent, so
    running it on the 7.3 lane is a consistency check that the down-level changed no emitted bytes,
    **not** a "proven on the floor" claim);
  - keep the `acceptance` job as-is for now (7.3 acceptance lands in Phase 8).
- `node --check` not applicable (no JS in core).

**Test first / verify:**
- `bash scripts/ci/parse-check.sh` under 8.4 → passes (8.4 accepts everything). Under 7.3 (Docker) →
  **fails** (RED — this is the failing test the conversion phases must turn green).
- `bash scripts/ci/anti-regression-lint.sh` → currently **reports the known sites** (expected; it flips
  to green as conversion completes — do **not** wire it as a hard-fail gate until Phase 7, or run it
  advisory-only until then). Confirm it reports exactly the inventory counts.
- YAML sanity: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/tests.yml'))"`.

**Done-criteria:** the 7.3 parse-check is a real, runnable, currently-RED command; the anti-regression
lint enumerates exactly the four-construct inventory; the workflow YAML is valid and the 7.3/7.4 matrix
rows exist. No `src`/`tests` behaviour changed.

---

## Phase 2 — Runtime leaf DTOs / value objects (promotion + typed props)

**Rationale for ordering:** leaves have the smallest autoload closure, so their tests run on 7.3 the
moment they and their test files are converted — the first place a *targeted 7.3 phpunit* can go green.

**Change:** convert (design §4.2.a/b recipes) the leaf value objects — no arrow fns here:
`src/RequestContext.php`, `src/TemplateMatch.php`, `src/SynthesizedResponse.php`, `src/Honeytoken.php`,
`src/Response/EmulatedContent.php`, `src/Response/RouteTemplateSet.php`, `src/Rules/RulesStatus.php`,
`src/Rules/UpdateResult.php`, `src/Compiler/Matcher/MatcherResult.php`, `src/Compiler/Bundle.php`,
plus `src/Rules/RulesLocator.php`'s `private static ?string $dataDir` (static typed prop → `@var`).
For each: promoted params → explicit untyped property + `@var <Type>` docblock + `$this->x = $x;`
assignment in the ctor body; keep the type **on the parameter**; keep default initialisers. Also
convert any arrow fns in the **test files** that exercise these DTOs so their targeted 7.3 run parses.

**Test first / verify:**
- The oracle is the **existing** DTO tests (already written) — no new tests needed; they encode the
  behaviour that must not change.
- Host: `php vendor/bin/phpunit` → still **baseline-count green**.
- 7.3, per converted file: `docker … php -l <file>` → clean.
- 7.3, targeted: `docker … php vendor/bin/phpunit --filter '(RequestContext|TemplateMatch|MatcherResult|…)'`
  → green for the converted leaves (each leaf's autoload closure is now 7.3-clean).

**Done-criteria:** all listed leaf files + `RulesLocator` static prop lint clean on 7.3; their existing
tests pass on both 8.4 and 7.3; host full suite still green at the recorded baseline; `@var` recovered on every de-typed
property (spot-check a sample against the original inline types).

---

## Phase 3 — Runtime engine core (promotion + typed props + 2 arrow fns)

**Change:** convert the request-path engine and its DTOs/emulators:
`src/Honeypot.php`, `src/Config.php` (20 promoted params — the largest single file; note the `?Closure`
knobs de-type to `/** @var Closure|null */`), `src/Detection.php` (incl. arrow fn at `:47`),
`src/Synthesis/ResponseSynthesizer.php`, `src/Response/RouteTemplateEmulator.php` (incl. arrow fn at
`:109`), `src/Response/EmulatorRegistry.php`, `src/Template/TemplateAttackEmulator.php`,
`src/Http/HoneypotMiddleware.php`. Arrow fns per design §4.2.c —
read each body, list exactly the captured vars in `use()`, keep `static` where present. Convert the
matching test files' arrow fns too.
- **`src/Laravel/HoneypotMiddleware.php` scope is conditional on Piece E (D9).** If E is extracting
  `src/Laravel/*` into its own package, **exclude those files here** — do not down-level files E deletes.
  Convert the Laravel bridge in this phase **only** if E is not extracting it (or has not landed first);
  whichever change lands first sets the inventory. Coordinate before touching `src/Laravel/*`.
- **Add the `Config` array/builder factory (M15).** In the same file, add the additive
  `Config::fromArray(array $overrides): self` per design §4.4 — a 7.3-callable factory that maps named
  keys onto the 20 constructor positions (defaulting unmapped params, rejecting unknown keys) so 7.3
  consumers (Piece D's `EngineFactory`) aren't pinned to positional order. This is the only *new* code
  in piece C; it changes nothing existing.

**Test first / verify:** existing engine/response/synthesis tests are the oracle for the conversion.
For the **new `Config::fromArray()` factory (M15), write a test first** (`ConfigFactoryTest`): assert
`Config::fromArray([])` equals the all-defaults constructor build; assert a couple of named overrides
land on the right fields (e.g. `pathScope`, `nucleiReflection`) and every *unmapped* param keeps its
default; assert an unknown key throws. This is the one place new behaviour exists, so it gets a real
first-written test.
- Host: `php vendor/bin/phpunit` → **baseline-count green** (now includes `ConfigFactoryTest`; the
  baseline recorded in Phase 0 rises by the new test — re-record it).
- 7.3, targeted at the engine test classes: `docker … php vendor/bin/phpunit --filter '(Honeypot|Config|Detection|ResponseSynthesizer|RouteTemplateEmulator|TemplateAttackEmulator|Middleware|ConfigFactory)'`
  → green (`Config::fromArray` must run on the 7.3 floor — plain static method + array arg).
- 7.3 parse sweep: failing-file set has shrunk by exactly this phase's files.

**Done-criteria:** engine files lint clean on 7.3; engine tests green on 8.4 and 7.3; each converted
arrow fn's `use()` verified by reading its body (no missing/spurious captures); **`Config::fromArray()`
exists, is 7.3-callable, and its test passes on 8.4 and 7.3**; host suite green at the (re-recorded)
baseline. If E is extracting `src/Laravel/*`, those files are not part of this phase's converted set.

---

## Phase 4 — Rules trust-chain subtree (promotion + typed props + 1 arrow fn)

**Rationale:** Invariant #3 (rules-update is RCE-adjacent). This subtree gets its own phase so the
trust-chain tests are an explicit tripwire on the floor.

**Change:** convert `src/Rules/*`: `RulesUpdater.php` (12 typed props + arrow fn at `:238`, captures
`$current`), `SignatureVerifier.php`, `KeyRing.php`, `CurlFetcher.php`, `ReDosGuard.php`,
`RulesUpdateException.php`, `PhpLiteralValidator.php` (if it carries any of the four — verify),
and any remaining `Rules/` DTOs not done in Phase 2. `PhpLiteralValidator` uses `token_get_all`, whose
token constants are stable 7.3→8.4 (design §6) — its logic is untouched; only syntax converts.

**Test first / verify:** the **`PhpLiteralValidator` + `SignatureVerifier` unit tests are the
tripwire** (design §6). ext-sodium must be present in the 7.3 container for signature tests — the
official `php:7.3-cli` image lacks it, so either `docker run … -e … ` with a sodium-enabled variant or
add an install step: `docker run --rm -v "$PWD":/app -w /app php:7.3-cli sh -c "pecl install libsodium >/dev/null 2>&1 || apt-get… ; php vendor/bin/phpunit --filter '(SignatureVerifier|PhpLiteralValidator|RulesUpdater|KeyRing|ReDosGuard)'"`. Simplest reliable path: build the one-off
`php:7.3-cli` + **`sodium`** image once (design §7; documented in Phase 1
harness notes) and reuse it for all 7.3 runs — `sodium` is what the rules trust-chain tests need to run
rather than skip. (D9's extra `pdo_sqlite` + `curl` were for Piece B's `src/Report/` tests, which under
**F** relocate to `metrictower/mainnet-client`; core no longer needs them, though they stay harmless.)
- Host: `php vendor/bin/phpunit` → **baseline-count green**.
- 7.3, targeted at the rules classes → green (**must** include the signature + literal-validator tests).

**Done-criteria:** entire `src/Rules/` subtree lints clean on 7.3; the trust-chain tests (signature
verify, sha256, array-literal validator) pass on 7.3 **and** 8.4 — Invariant #3 proven on the floor;
no logic diff in the trust chain (review the diff for syntax-only changes).

---

## Phase 5 — Compiler subtree (typed props + `??=` + the bulk of the arrow fns)

**Change:** convert `src/Compiler/**`: `Compiler.php`, `LoadedTemplate.php`, `SatisfyPlan.php`,
`ClassifiedTemplate.php`, `Classifier.php` (arrow fn `:187`, captures `$forbidden`), `ArtifactWriter.php`,
`TemplateLoader.php` (arrow fns `:81` captures nothing, `:82` captures nothing),
`Crs/CrsCompiler.php` (**the `??=` at `:72`** per §4.2.d + arrow fn `:200`), `Crs/CrsRule.php`,
`Crs/CrsArchetypes.php` (arrow fn `:130`), `Crs/FingerprintGuard.php`, `Crs/RegexAggregator.php`
(arrow fn `:94`), `Crs/CrsRuleParser.php` (arrow fn `:210`), `Matcher/RegexWitness.php`,
`Matcher/DslInverter.php` (arrow fns `:45`, `:378`), `Matcher/RegexWitnessGenerator.php` (arrow fn `:57`),
`Matcher/WordMatcherInverter.php` (arrow fns `:53`, `:112`), and `Store/PhpArrayStore.php`. `??=`
recipe: `$classes[$class] = $classes[$class] ?? [...]`. Convert compiler test files' arrow fns too.
- **No `src/Report/` to fold (F, supersedes D9).** B's reporter relocates to the standalone
  `metrictower/mainnet-client` package (`Funnypot\Mainnet\Reporter`), which carries its own PHP `>=7.3`
  CI lane — it never lands in core, so this sweep has no `src/Report/*` to convert or police. The
  earlier D9 "fold `src/Report/` into C's gate" step is dropped. C's only tie to B is the runtime
  `require` on `mainnet-client` added in Phase 7.

**Test first / verify:** existing compiler tests are the oracle (they autoload compiler classes — this
is exactly why the design chose a whole-tree floor, §8.1).
- Host: `php vendor/bin/phpunit` → **baseline-count green**.
- 7.3 parse sweep over `src` should now be **fully clean** (all `src` files converted): 
  `docker … sh -c "find src -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null"` → exit 0.
- 7.3 targeted at compiler test classes → green.

**Done-criteria:** **all of `src/` lints clean on 7.3**; the single `??=` and every one of the 15 src
arrow fns converted (grep for `\bfn\s*\(` in `src` returns only the 6 `Config.php` docblock comment
lines); compiler tests green on 8.4 and 7.3; host suite green at the recorded baseline.

---

## Phase 6 — `tests/` remainder & full 7.3 suite green

**Change:** convert any remaining arrow fns and 8.x constructs in `tests/` not already handled in the
cluster phases (target total: the 22 `tests/` arrow-fn sites, plus any promotion/typed props in test
fixtures/helpers). After this, the entire `tests/` tree parses on 7.3.

**Test first / verify:** the full 7.3 suite is now runnable end-to-end — this is the phase's own test.
- Host: `php vendor/bin/phpunit` → **baseline-count green**.
- 7.3 full: `docker … php vendor/bin/phpunit` → green with **the same tests/assertions pair the 8.4 host
  reports** (run-and-compare against the re-recorded Phase-0/Phase-3 baseline — behaviour equivalence on
  the floor). Do **not** assert a literal 327/4190 (D9): the count includes `ConfigFactoryTest` (there
  are **no** `src/Report/` tests in core under F), and both interpreters must land on the *same* number
  **with the rules trust-chain's `sodium`-conditional tests present in both** (a skipped test on one
  side is a divergence to fix, not to accept).
- 7.3 parse sweep over `src tests` → exit 0.
- `bash scripts/ci/anti-regression-lint.sh` → now **green** (zero sites); flip it to a hard-fail gate.

**Done-criteria:** full suite green on **both** 8.4 and 7.3 with **matching** test/assertion counts
(dynamic, not a hardcoded pair); parse sweep clean; anti-regression lint green and enforced.

---

## Phase 7 — composer floor bump + polyfill

**Change (design §3 / §4.3):**
- `composer.json`: `"php": ">=8.0"` → `">=7.3"`.
- **Add a runtime `require` on `metrictower/mainnet-client` (F).** This is the relocated reporter's new
  home (`Funnypot\Mainnet\Reporter`), a PHP `>=7.3` package core re-exports so the WP/Laravel bridges
  get it transitively. The require **must resolve on the new 7.3 floor** — verified below.
- **Narrow require-dev `symfony/yaml` from `"^5.4 || ^6.0"` to `"^5.4"` (BL1).** The `^6.0` arm resolves
  to v6.4.43 (`php>=8.1`), which cannot install or parse on 7.3 and would make the new 7.3/7.4 lanes
  fail before phpunit boots. (Equivalent alternative: keep the constraint but add
  `config.platform.php: "7.3"` so any re-resolve is forced onto the 7.3-capable arm — pick one; the
  narrowing is simpler and self-documenting.)
- Add `"symfony/polyfill-php80": "^1.28"` to `require` (forward-guard; a no-op today since core uses
  zero 8.0 runtime functions — grep confirms 0 hits — and it carries **no fingerprint risk**: it is a
  set of global function shims, invisible in any HTTP response). *Confirm-at-review flag:* add the dep
  vs. stay dependency-light and rely on the lint alone (design leans "add it").
- `composer update --lock` to regenerate `composer.lock` for the new constraints (this must now pin a
  **5.4.x** symfony/yaml, not 6.x).

**Test first / verify:**
- `composer validate --strict` → passes.
- **BL1 lock assertion (write it as a checked step):** grep/parse `composer.lock` and assert the locked
  `symfony/yaml` is a **5.4.x** release (e.g. `php -r '...json_decode(file_get_contents("composer.lock"))...'`
  or `composer show symfony/yaml | grep -E "versions\s*:\s*\*?\s*v?5\.4"`) → fail the phase if it is 6.x.
- **F dependency-floor assertion (write it as a checked step):** parse `composer.lock` and assert the
  locked `metrictower/mainnet-client` declares a `"php"` constraint satisfied by `>=7.3` (`composer show
  metrictower/mainnet-client` / read its `require.php`) → fail the phase if it ever demands `>8.0`. A
  mainnet-client release that raised its own floor would silently re-break core on the WP hosts C exists
  for. This is confirmed by the 7.3 `composer install` succeeding below.
- `composer install` on the 7.3 container from the regenerated lock → **resolves and passes the
  platform check** (it would have failed here with 6.4.43); then `docker … php vendor/bin/phpunit` →
  **baseline-count green** (deps still satisfy 7.3).
- Host: `composer install && php vendor/bin/phpunit` → **baseline-count green** (8.x unaffected).

**Done-criteria:** floor is `>=7.3`; **runtime `require` on `metrictower/mainnet-client` added and the
locked release resolves on the 7.3 floor (F, asserted)**; require-dev `symfony/yaml` is `^5.4` and the
**lock pins 5.4.x** (asserted); lock regenerated and installs on 7.3 and 8.4; suite green on both;
`composer validate --strict` clean. Polyfill decision recorded.

---

## Phase 8 — 7.3 acceptance lane + downstream re-resolve check

**Change:**
- CI: add a 7.3 real-nuclei acceptance lane in `tests.yml` (design §6/§7) — duplicate the `acceptance`
  job with `php-version: '7.3'` (keep the 8.3 lane too), running `bash tests/acceptance/run.sh`. This
  proves the *runtime* path piece D depends on, on the floor — the strongest evidence for D.
- Verify the fingerprint gate runs green in the 7.3 lane (Invariant #1):
  `php scripts/ci/check-fingerprint-safety.php`. (Consistency check on a static, version-independent
  artifact — not a floor-specific proof; that wording is reserved for the runtime acceptance lane above.)
- **Add a funnypot-rules 7.3 parse gate (nit / design §6).** The publish side of the rules-update feed
  must `php -l` every emitted `.php` rule artifact under a **7.3** interpreter before signing/publishing,
  so once core runs on the 7.3 floor (Piece D's hosts) no fetched-and-`require`d artifact can fatal on
  8.x/7.4 syntax that the signature + literal validator would not catch. Land it as a step in the
  funnypot-rules build/publish workflow (or, if that repo is out of C's reach, record it here as a
  required companion gate for the 7.3 release to be safe for D to consume).

**Test first / verify:**
- Locally (if Docker + nuclei available) run `tests/acceptance/run.sh` against a `php -S` server booted
  under 7.3; assert every golden template still fires (the harness writes `fired.txt`/`golden.txt`).
- **Downstream guard (design §9):** in the funnypot **app** repo run
  `composer update metrictower/funnypot-core` and confirm `composer.lock` still resolves and the app's
  floor stays `>=8.0` (intersection `>=8.0 ∩ >=7.3 = >=8.0`). Run the app suite green. The app
  `composer.json` must **not** change.

**Done-criteria:** 7.3 acceptance job passes real nuclei on the floor; fingerprint + license gates green
on the 7.3 lane; app `composer update` re-resolves with an unchanged `>=8.0` floor and the app suite is
green. Ready to tag a 7.3-capable core release for piece D to consume.

---

## Risks & open decisions

1. **`php -l` on 8.4 gives false confidence** (it accepts 7.4/8.0 syntax). *Mitigation:* all 7.3
   verification goes through a real `php:7.3-cli` container; the parse-check is meaningless unless run
   there. This is the single biggest process risk — a builder who skips Docker will "pass" locally and
   ship broken 7.3.
2. **ext-sodium on 7.3.** The stock `php:7.3-cli` image lacks sodium; the rules trust-chain tests
   (Invariant #3) need it. *Mitigation:* build a one-off `php:7.3-cli`+sodium image in Phase 1 and reuse
   it for all 7.3 runs; document the exact `docker build` snippet in the harness notes. Open: pin the
   sodium version, or rely on the distro pecl build.
3. **Arrow-fn `use()` capture is the only judgement call** (design §4.2.c). A missed capture is a
   *runtime* bug that a parse-check won't catch — only the behavioural suite will. *Mitigation:* convert
   per-site by reading the body; the existing tests on 7.3 are the oracle; never regex-convert arrow fns.
4. **De-typed properties lose runtime type enforcement** (moves to `@var` docblocks). *Accepted* per
   design §6/decision 2 — parameter types (the real validation boundary) are retained. Fast-follow
   PHPStan pass (design §2, out of scope here) re-asserts the `@var` types.
5. **Polyfill dep — add or not** (design decision 5, still open for review). Plan adds it in Phase 7 but
   flags it; trivially reversible.
6. **Acceptance-on-7.3 feasibility.** Requires Docker + nuclei in CI (already used by the 8.3 lane). If
   the 7.3 image + nuclei combo is flaky, fall back to **7.3 unit coverage + 8.3 acceptance** (design
   §7 minimum) and open a follow-up. Not a blocker for merge.
7. **Anti-regression lint false positives.** The typed-prop / promotion regexes can misfire on
   docblocks or multiline signatures. *Mitigation:* tune against the current tree in Phase 1 (must report
   exactly the inventory), keep it advisory until Phase 6, enforce only once it reads zero.

---

## Definition of done

- [ ] `src/` and `tests/` parse clean on **real PHP 7.3** (Docker sweep exits 0).
- [ ] `php vendor/bin/phpunit` → green with **matching tests/assertions counts on both 8.4 and 7.3**,
      compared to the **Phase-0 recorded baseline** (run-and-compare, D9 — not a hardcoded 327/4190; the
      count includes `ConfigFactoryTest` — there are **no** `src/Report/` tests in core under F — and the
      rules trust-chain's `sodium`-conditional tests must run, not skip, on both lanes because the 7.3
      container carries `sodium`).
- [ ] The four constructs are gone from `src` and `tests` (grep-verified); anti-regression lint green
      and wired as a hard gate in `tests.yml`.
- [ ] `composer.json` floor = `>=7.3`; **runtime `require` on `metrictower/mainnet-client` added and its
      locked release resolves on the 7.3 floor (F, asserted in Phase 7)**; **require-dev `symfony/yaml`
      narrowed to `^5.4` and the lock pins a 5.4.x release (BL1, asserted in Phase 7)**; `composer.lock`
      regenerated, installs on 7.3 and 8.4; `composer validate --strict` clean; polyfill decision recorded.
- [ ] **`Config::fromArray()` factory exists (M15), is 7.3-callable, and `ConfigFactoryTest` passes on
      8.4 and 7.3** — 7.3 consumers build `Config` by named keys, not positional order.
- [ ] **No `src/Report/` in core (F, supersedes D9)** — B's reporter relocates to
      `metrictower/mainnet-client`, so it is not in C's conversion scope; C requires the package instead;
      **`src/Laravel/*` excluded from C's scope if E extracts it.**
- [ ] **funnypot-rules publish gate:** every published `.php` rule artifact `php -l`-clean on 7.3
      (design §6) so the 7.3 release is safe for D to consume.
- [ ] CI `tests.yml` matrix includes `7.3` and `7.4`; parse-check runs in the 7.3 lane and is green; the
      fingerprint-safety gate runs green in the 7.3 lane as a version-independent consistency check
      (**Invariant #1** — not a floor-specific proof, since it scans a static artifact).
- [ ] Rules trust-chain tests (signature verify, sha256, `PhpLiteralValidator`) pass on 7.3 —
      **Invariant #3 preserved**; trust-chain diff is syntax-only.
- [ ] 7.3 real-nuclei acceptance lane green (or documented fallback to 7.3-unit + 8.3-acceptance).
- [ ] No public API / class name / method signature / compiled-artifact-format change (diff is
      mechanical only; a consumer on 8.x keeps working byte-for-byte).
- [ ] Downstream: funnypot **app** `composer update metrictower/funnypot-core` re-resolves with the
      app floor unchanged at `>=8.0`; app suite green; app `composer.json` untouched.

---

## Key decisions I made (confirm at review)

1. **Verification runs through a Docker `php:7.3-cli` container, not host `php -l`.** The host is PHP 8.4
   and its linter accepts the very syntax we are removing, so it cannot produce the failing signal. I
   made the 7.3 container the mandatory harness and built the whole TDD RED→GREEN loop on it. If CI is
   preferred as the only 7.3 oracle, the local Docker step is optional but strongly recommended for a
   tight loop.
2. **Phase ordering is dependency-driven (leaves → engine → rules → compiler → tests), not
   construct-driven.** `php -l` is per-file but a *targeted 7.3 phpunit run* needs the target's whole
   autoload closure converted; leaf-first ordering is what makes each phase independently 7.3-verifiable.
   The design listed the surface by construct; I re-sequenced it by autoload-closure for TDD.
3. **Rules trust-chain gets its own phase (Phase 4)** ahead of the larger compiler subtree, so
   Invariant #3's tripwire tests are exercised on 7.3 as early as possible, and the sodium-in-7.3
   harness wrinkle is solved before the bulk of the work.
4. **The "test written first" is the 7.3 harness + parse-check + anti-regression lint (Phase 1), landed
   RED before any conversion.** The one exception is `ConfigFactoryTest` for the new
   `Config::fromArray()` factory (M15) — genuinely new behaviour, so it gets a real first-written test.
   Otherwise no new behavioural tests are added — the existing suite (at its dynamically recorded count)
   is the behaviour-equivalence oracle, which is the correct discipline for a pure mechanical down-level.
5. **Anti-regression lint is advisory until Phase 6, then hard-fail.** It necessarily reports the known
   sites while conversion is in flight; enforcing it earlier would block the very phases doing the work.
6. **Polyfill added in Phase 7 (following the design's lean) but flagged** as the one genuinely optional
   dep decision; trivially reversible if review prefers dependency-light + lint-only.
7. **7.3 acceptance lane is planned (Phase 8) with an explicit documented fallback** (7.3 unit + 8.3
   acceptance) so a nuclei-on-7.3 CI flake cannot block the merge.

---

## Dependencies on other pieces

- **Piece D (honeypot-wordpress) hard-depends on C.** D cannot start consuming core until C merges and a
  **7.3-capable core release is tagged**. Phase 8's downstream check + a tag are D's entry gate. D builds
  its engine `Config` through C's **`Config::fromArray()` factory** (M15, Phase 3), not a hand-rolled
  positional constructor call.
- **Piece B (report-to-mainnet) relocates its reporter to `metrictower/mainnet-client` (F, supersedes
  D9).** B's `MainnetReporter` becomes `Funnypot\Mainnet\Reporter` in the standalone package, not
  `Funnypot\Report\*` in core — so **no `src/Report/` tree lands in core** and there is nothing for C to
  convert or police. The package owns its own PHP `>=7.3` CI lane; B and C are policed by separate gates
  in separate repos. C's only tie to B is the runtime `require` on `metrictower/mainnet-client` (Phase
  7), which **must resolve on the 7.3 floor** (asserted). Both the D9 "fold `src/Report/` into C's gate"
  arrangement and the older "B stays app-side, no conflict" claim it replaced are **dropped**.
- **Piece E (honeypot-laravel):** independent of C for its *floor* (Laravel hosts run 8.x), but the file
  scopes can collide (D9): if E extracts `src/Laravel/*` into its own package, C **excludes those files
  from conversion** — C must not down-level files E deletes; whichever lands first sets C's inventory.
  Otherwise a 7.3-clean core is a strict superset of what E needs, imposing no additional floor
  constraint.
- **funnypot app:** must **not** lower its own floor — stays `"php": ">=8.0"`. Phase 8 verifies the app's
  `composer.lock` still resolves against the widened core constraint (`>=8.0 ∩ >=7.3 = >=8.0`).
- **No dependency on A1 (mainnet-api) or A2 (mainnet-web).**

---

## Review resolutions applied (2026-08-19)

- **BL1** — Orientation: corrected the "all dev deps already 7.3-compatible" claim; flagged that
  `symfony/yaml` is constrained `^5.4 || ^6.0` and the lock pins **v6.4.43** (`php>=8.1`), which blocks
  the 7.3 lanes. Phase 7: narrow require-dev to `^5.4` (or add `config.platform.php: "7.3"`), regenerate
  the lock, and **assert the locked `symfony/yaml` is 5.4.x** as a checked step; added the platform-check
  pass to the 7.3 install verify. Definition of done updated with the 5.4.x pin.
- **D9** — Orientation + Docker harness note + Phase 4: the 7.3 verification container must carry
  `sodium` so the rules trust-chain's conditional tests run, not skip. Baseline is now **captured
  dynamically** (Phase 0 records the reported tests/assertions pair; every phase does run-and-compare) —
  removed the hardcoded "327 tests / 4190 assertions" oracle throughout (Orientation, TDD framing,
  Phases 0/2/3/4/5/6/7, Definition of done, Key decisions). Phase 3 + Dependencies: `src/Laravel/*`
  excluded from C's scope if E extracts it. Dropped the "B stays app-side / no conflict" claim in the
  Dependencies section. *(The `src/Report/`-fold portion and its `pdo_sqlite` + `curl` container
  requirement are later reverted by F below — the reporter leaves core entirely; the `sodium`
  requirement and the `src/Laravel/*` exclusion stand.)*
- **F relocation** (decision F, `funnypot-mainnet/docs/2026-08-19-program-decisions.md`) — B's reporter
  relocates from `funnypot-core/src/Report/` into the new standalone `metrictower/mainnet-client` package
  (`Funnypot\Mainnet\Reporter`), which carries its own PHP `>=7.3` CI. **Removed `src/Report/` from C's
  conversion scope** (it never lands in core), reverting the D9 fold: Orientation baseline note + Docker
  harness note (dropped the `pdo_sqlite`/`curl`-for-Report rationale; kept `sodium` for rules), Phase 0
  (no `src/Report/*` in the failing set), Phase 4 (container needs `sodium`, not the three-extension set),
  Phase 5 (no `src/Report/` to fold), Phase 6, Dependencies (Piece B bullet rewritten), Definition of
  done. **Added the runtime `require` on `metrictower/mainnet-client`** (Orientation, Phase 7) with a
  checked assertion that the locked release resolves on the 7.3 floor, plus a Definition-of-done item.
  C's construct inventory (promotion / typed props / arrow-fns / `??=`) is unchanged apart from dropping
  the `src/Report/` references.
- **M15** — Phase 3: added the `Config::fromArray()` array/builder factory as a task with a
  **test-first `ConfigFactoryTest`** and a done-criterion; Dependencies + Definition of done note D builds
  `Config` through it.
- **Nit (arrow-fn count)** — Orientation surface table: arrow-fn `13 → 12` src files.
- **Nit (Config params)** — Phase 3: `Config.php` promoted params `23 → 20`.
- **Nit (lint regex)** — Phase 1: broadened the anti-regression typed-prop type token to match
  FQCN/namespaced, nullable, and union tokens (not just `\w+`) and added a namespaced-type fixture to the
  self-test.
- **Nit ("proven on the floor")** — Phase 1 + Definition of done: reframed the fingerprint-safety gate as
  a version-independent consistency check on a static artifact, not a floor-specific proof (kept the
  phrase only for the runtime acceptance and trust-chain lanes, which are genuinely interpreter-dependent).
- **Nit (rules artifacts on 7.3)** — Phase 8 + Definition of done: added a funnypot-rules publish gate
  that `php -l`-checks every published `.php` rule artifact on 7.3 before signing/publishing.
