# funnypot-core · Piece C (core-php73) — design spec

**Status:** draft for review · **Date:** 2026-08-19 · **Piece:** C of the funnypot-mainnet program
**Prereq for:** Piece D (honeypot-wordpress) — WP hosts run PHP 7.x, so the engine must parse and run on 7.3.

---

## 1. What this is

Lower the **language floor of `metrictower/funnypot-core` from PHP 8.0 to PHP 7.3** so the engine
embeds cleanly in old-PHP hosts (shared hosting, legacy WordPress installs) without dragging an 8.x
requirement in. This is a **syntax down-level plus composer floor change** — no behaviour change to any
existing path, no changed API. The one **additive** exception is a 7.3-callable `Config` array/builder
factory (§4.4, M15) that lets 7.3 consumers build `Config` without named arguments; it adds a method and
changes nothing existing. The runtime stays framework-free and the compiled-artifact contract is untouched. The codebase was already written with a conservative-PHP discipline (see
`src/Outcome.php`: *"String constants, not an enum, for PHP 8.0."*), so the surface to convert is
small and well-bounded: it is dominated by **constructor property promotion** (8.0) and **typed
properties / arrow functions** (7.4), with essentially nothing else.

## 2. Scope

### v1 (this spec)

- Convert **all of `src/`** (runtime *and* compiler subtrees) plus the `tests/` suite to parse and run
  on PHP 7.3–8.4.
- **Piece B's reporter is NOT in C's scope (F, supersedes D9).** B's `MainnetReporter` relocates out of
  `funnypot-core/src/Report/` into the standalone `metrictower/funnypot-mainnet-client` package as
  `Funnypot\Mainnet\Reporter`; it never lands in core, so there is no `src/Report/` tree for C to
  down-level or police. The package carries its own PHP `>=7.3` CI lane. This reverts the earlier D9
  "fold `src/Report/` into C's 7.3 matrix" decision.
- **`funnypot-core` requires `metrictower/funnypot-mainnet-client` (F).** Add a composer `require` on the new
  standalone package (itself PHP `>=7.3`, dependency-light, with its own 7.3 CI); core re-exports it so
  the WP/Laravel bridges get it transitively. The require **must resolve on core's new 7.3 floor** —
  Phase 7 asserts the locked `mainnet-client` satisfies `>=7.3` (§4.3, §7).
- **`src/Laravel/*` scope depends on Piece E (D9).** If E extracts the Laravel bridge into its own
  package, those files are **removed from core** and are therefore **excluded from C's conversion
  scope**; reflect whichever change (E's extraction or C's conversion) lands first in C's inventory
  counts. Do not both convert and delete the same files.
- **Expose a 7.3-callable factory for `\Funnypot\Config` (M15).** 7.3 has no named arguments, so a
  positional build against `Config`'s ~20-param promoted constructor is order-fragile and
  silent-misassignment-prone for 7.3 consumers (Piece D's `EngineFactory`). Add a small
  **array/builder factory** — e.g. `Config::fromArray(array $overrides)` — that maps named keys to the
  right constructor positions with defaults for everything unmapped, so 7.3 callers are not pinned to
  positional order. Public, additive API (no signature change to the existing constructor).
- `composer.json`: `"php": ">=8.0"` → `">=7.3"`; narrow require-dev `symfony/yaml` to `^5.4` (BL1, §3).
- Add a **7.3 (and 7.4) lane** to the CI test matrix; keep the fingerprint-safety and license gates
  green on every lane.
- No public API, class name, method signature, or compiled-artifact-format change (the `Config`
  factory is a new **additive** method — it changes nothing existing). A consumer that works on 8.x
  today keeps working byte-for-byte.

### Non-goals / explicit decisions

- **Not** dropping to a still-lower floor (7.2 / 7.1). 7.3 is the target because PHPUnit ^9 needs 7.3+
  and 7.3 is the realistic old-WordPress floor; going lower buys nothing for piece D and costs the
  flexible-heredoc/trailing-comma-in-calls conveniences 7.3 gives us.
- **Not** carving a "runtime-only" sub-package with a separate floor (considered — see §8). One honest
  repo-wide floor is simpler and keeps the full test suite meaningful on 7.3.
- **No** behavioural refactors ride along. This is a mechanical down-level; anything else is a
  separate change.
- **Fast-follow:** an optional static-analysis/PHPStan pass to re-assert the recovered `@var` types
  (types move from syntax into docblocks — see §4.2).

## 3. Architecture

Nothing about *where core runs* changes; only *which PHP parses it*.

```
  Today                                   After piece C
  ─────                                   ─────────────
  composer: php >=8.0                     composer: php >=7.3
  CI: 8.0 8.1 8.2 8.3 8.4                  CI: 7.3 7.4 8.0 8.1 8.2 8.3 8.4
        │                                       │
        ▼                                       ▼
  funnypot app (php >=8.0)  ─── requires ──► funnypot-core  ◄── embeds ── honeypot-wordpress (PHP 7.x host)
        (unchanged; 8.x floor kept)                              (piece D — the reason C exists)
```

- **Stack:** framework-free PHP library. Runtime `require` gains **`metrictower/funnypot-mainnet-client`** (F —
  the relocated reporter's package; itself PHP `>=7.3`, dependency-light), which core re-exports; this
  is the one *runtime* dependency added by the program and it must satisfy the 7.3 floor (§4.3).
  `require-dev` is PHPUnit ^9.5, nyholm/psr7 ^1.8, the PSR HTTP interfaces, and symfony/yaml. PHPUnit 9
  requires `>=7.3`; nyholm/psr7 and the psr/* interfaces require `>=7.2` — those are already
  7.3-compatible and need no change.
- **symfony/yaml must be pinned to the 5.4 arm (BL1).** The constraint is currently
  `"symfony/yaml": "^5.4 || ^6.0"` and the committed `composer.lock` resolves the 6.x arm — it pins
  **symfony/yaml v6.4.43**, whose own `"php": ">=8.1"` **cannot install or parse on 7.3**. Left as-is,
  Phase 7's `composer update --lock` on the 8.4 build host re-resolves 6.x, `composer install` on
  `php:7.3-cli` fails the platform check, and the 7.3/7.4 CI lanes never boot phpunit. **Fix:** narrow
  the require-dev constraint to **`"symfony/yaml": "^5.4"`** (5.4 needs only `>=7.2.5`) and regenerate
  the lock so it pins a 5.4.x release (equivalently, add `config.platform.php: "7.3"` to
  `composer.json` and re-resolve). A Phase-7 assertion checks the locked `symfony/yaml` is 5.4.x. This
  is the one dev-dependency that needs pinning; nothing needs downgrading below its floor.
- **ext-sodium / ext-openssl** are *runtime extensions* (the pure-PHP SSH server), present on both 7.3
  and 8.x; the floor change does not touch them. They stay under `suggest`.

## 4. The concrete surface

### 4.1 Real inventory (grepped from `funnypot-core/src`, 2026-08-19)

| Construct | Introduced | Real occurrences in `src/` | Files | Disposition |
|---|---|---|---|---|
| **Constructor property promotion** | 8.0 | **94 promoted params** | **19** | **Convert** (§4.2.a) |
| **Class-level typed properties** | 7.4 | **101 standalone decls** (+ the 94 promoted ones) | **24** | **Convert** (§4.2.b) |
| **Arrow functions `fn()`** | 7.4 | **15** (+22 in `tests/`) | 12 | **Convert** (§4.2.c) |
| **`??=` (null-coalescing assign)** | 7.4 | **1** (`src/Compiler/Crs/CrsCompiler.php:72`) | 1 | **Convert** (§4.2.d) |
| `match` expression | 8.0 | 0 (the 3 `match(` hits are a method named `match` + a comment) | — | none |
| `enum` | 8.1 | 0 (deliberately avoided — `Outcome.php`, `Style.php`, `Severity.php` use class constants) | — | none |
| `str_contains` / `str_starts_with` / `str_ends_with` | 8.0 | 0 | — | none (polyfill is a forward-guard only, §4.3) |
| Nullsafe `?->` | 8.0 | 0 | — | none |
| Named arguments (call sites) | 8.0 | 0 | — | none |
| Union types (`A\|B`) | 8.0 | 0 (2 hits are `@param array\|string` docblocks) | — | none |
| `mixed` type | 8.0 | 0 (all 82 hits are `array<string,mixed>` docblocks) | — | none |
| `readonly` | 8.1 | 0 | — | none |
| `static` return type | 8.0 | 0 | — | none |
| First-class callable `(...)` | 8.1 | 0 (5 hits are `tolower(...)`-style comments) | — | none |
| `throw` as expression | 8.0 | 0 | — | none |
| Non-capturing `catch (X)` | 8.0 | 0 | — | none |
| `$obj::class` | 8.0 | 0 | — | none |
| Attributes `#[...]` | 8.0 | 0 | — | none |
| Array spread `[...$x]` | 7.4 | 0 (6 hits are comments) | — | none |
| Numeric separators `1_000` | 7.4 | 0 | — | none |
| Trailing comma in **param list** | 8.0 | 0 | — | none |
| `new` in initializer/default | 8.1 | 0 | — | none |

**The entire job is four constructs.** Everything an attacker-style "throw the whole 8.x feature list
at it" audit would look for is already absent — a direct consequence of the pre-existing discipline.
Constructs that are **fine on 7.3 and stay untouched**: nullable types `?T` (7.1), `void` return (7.1),
`object` type (7.2), `self`/`parent`/`array`/`callable` returns, `Closure` typehints, class-constant
visibility (7.1), flexible heredoc (7.3), and **trailing comma in function *calls*** (added in 7.3).

### 4.2 Conversion recipes

**(a) Constructor property promotion → explicit property + assignment.** On 7.3 the property
declaration *also* cannot carry a type (typed properties are 7.4), so the type lives only on the
constructor parameter and is recovered as a `@var` docblock on the property.

```php
// BEFORE (8.0) — src/Honeypot.php
public function __construct(
    private CompiledStore $store,
    ...
) { ... }

// AFTER (7.3)
/** @var CompiledStore */
private $store;

public function __construct(
    CompiledStore $store,   // param type declarations are fine on 7.3
    ...
) {
    $this->store = $store;
    ...
}
```

The 19 promotion files: `RequestContext`, `Honeypot`, `Honeytoken`, `Config`, `TemplateMatch`,
`SynthesizedResponse`, `Detection`, `Response/RouteTemplateSet`, `Response/EmulatedContent`,
`Response/RouteTemplateEmulator`, `Response/EmulatorRegistry`, `Template/TemplateAttackEmulator`,
`Synthesis/ResponseSynthesizer`, `Http/HoneypotMiddleware`, plus the DTOs. `Config.php` (20 promoted
params) and `RequestContext.php` (8) are the largest single conversions. Default values that reference
class constants (`Style::MINIMAL`) or `null` stay on the parameter unchanged — those are legal 7.3
defaults.

**(b) Class-level typed property → untyped property + `@var`.** Same de-typing move, for the 101
standalone typed properties (heaviest in `Compiler/Bundle.php` ×12, `Compiler/Matcher/MatcherResult.php`
×12, `Rules/RulesUpdater.php` ×12, `Rules/RulesStatus.php` ×7, `Rules/UpdateResult.php` ×6). Also
covers **static** typed properties (`Rules/RulesLocator.php`: `private static ?string $dataDir = null;`
→ `/** @var string|null */ private static $dataDir = null;`).

```php
// BEFORE (7.4) — src/Compiler/Matcher/MatcherResult.php
public ?array $statusAllowed = null;
public bool   $wholeBodyExclusive = false;

// AFTER (7.3)
/** @var array|null */ public $statusAllowed = null;
/** @var bool */       public $wholeBodyExclusive = false;
```

Default-value initialisers (`= []`, `= null`, `= false`, `= ''`, `= 0`) are all legal 7.3 property
defaults and stay.

**(c) Arrow function `fn()` → closure with explicit `use()`.** The one place needing *judgement*:
`fn` auto-captures by value; the rewritten closure must list exactly the outer variables the body
reads. Convert per-site, not with a blind regex.

```php
// BEFORE (7.4) — src/Compiler/Classifier.php:187
static fn (int $s): bool => !isset($forbidden[$s])
// AFTER (7.3)
static function (int $s) use ($forbidden): bool { return !isset($forbidden[$s]); }

// BEFORE — src/Rules/RulesUpdater.php:238  (captures $current)
fn ($v) => $v !== $current
// AFTER
function ($v) use ($current) { return $v !== $current; }

// BEFORE — src/Compiler/TemplateLoader.php:81  (captures nothing)
static fn ($p): string => (string) $p
// AFTER
static function ($p): string { return (string) $p; }
```

12 src files (15 sites) + 22 sites in `tests/`. Most are `static fn` inside `array_map`/`array_filter`
and capture zero-or-one variable; each site's `use()` is decided by reading the body.

**(d) `??=` → explicit `?? ` assignment.** One site.

```php
// BEFORE (7.4) — src/Compiler/Crs/CrsCompiler.php:72
$classes[$class] ??= ['rx' => [], 'pm' => [], 'rules' => [], 'severity' => 'low'];
// AFTER (7.3)
$classes[$class] = $classes[$class] ?? ['rx' => [], 'pm' => [], 'rules' => [], 'severity' => 'low'];
```

`$class` is a plain scalar key, so single-vs-double key evaluation is not a concern; `??` suppresses
the undefined-index notice on the read exactly as `??=` did.

### 4.3 composer.json diff + polyfill

```jsonc
"require": {
    "php": ">=7.3",                        // was ">=8.0"
    "metrictower/funnypot-mainnet-client": "^1.0"   // F — relocated reporter's home; PHP >=7.3 itself
    // OPTIONAL forward-guard (see below):
    // "symfony/polyfill-php80": "^1.28"
},
"require-dev": {
    "symfony/yaml": "^5.4"                 // was "^5.4 || ^6.0" — 6.x pins v6.4 (php>=8.1), BL1
    // …other dev deps unchanged…
}
```

After editing the constraint, regenerate the lock (`composer update symfony/yaml --lock`) so it pins a
5.4.x release; Phase 7 asserts the locked version is 5.4.x. (Alternatively, keep `^5.4 || ^6.0` but add
`config.platform.php: "7.3"` so any re-resolve is forced onto the 7.3-capable arm.)

- **`metrictower/funnypot-mainnet-client` require must resolve on the 7.3 floor (F).** The new dependency is a
  PHP `>=7.3` package, so it installs on core's widened floor — but that is a claim to *check*, not
  assume. After regenerating the lock, assert the locked `mainnet-client` release declares `"php"` that
  is satisfied by `>=7.3` (Phase 7), and that `composer install` succeeds on the 7.3 container. A
  mainnet-client release that ever raised its own floor above 7.3 would silently re-break core on the
  WP hosts C exists to serve.
- **Downstream effect (the app stays 8.x):** the funnypot app declares `"php": ">=8.0"` and requires
  core as `dev-main`. Composer resolves the *intersection* of the two constraints (`>=8.0` ∩ `>=7.3` =
  `>=8.0`), so **lowering core's floor cannot pull the app down** — the app still demands 8.0 for
  itself. Widening core's floor only *adds* hosts core can run on; it removes nothing.
- **Polyfill:** `symfony/polyfill-php80` supplies `str_contains`/`str_starts_with`/`str_ends_with`/
  `get_debug_type` at runtime. **Current core uses none of these** (grep: 0 hits), so the polyfill is a
  *no-op today* and is a forward-guard only — it lets a future contributor write `str_contains(...)`
  without breaking 7.3. Recommendation: **add it to `require`** (it is tiny, ubiquitous, and — being a
  set of global function shims, invisible in any HTTP response — poses **no fingerprint risk**, which
  is about response bytes, not composer deps). The lint in §7 is the belt to the polyfill's braces.
- **ext-sodium / ext-openssl** unaffected — runtime extensions, not language level.

### 4.4 `Config` array/builder factory (M15)

`\Funnypot\Config` has a single promoted constructor with **20 params** (see §4.2.a). On 8.x, callers
lean on **named arguments** to set a subset and skip middle params (core's own `buildConfig` does
this). 7.3 has no named args, so a 7.3 consumer must pass params **1..N positionally in exact order** —
including ones it doesn't care about — and a wrong count silently misassigns every later argument
(positional args don't error). To keep 7.3 consumers (Piece D) off that footgun, core exposes an
additive factory:

```php
// New, additive — does not touch the existing constructor.
public static function fromArray(array $overrides): self
{
    // Map named keys → the promoted-constructor positions, defaulting anything unmapped.
    // Unknown keys are rejected so a typo can't silently no-op.
    ...
    return new self(/* params 1..20 assembled here, in order */);
}
```

This lives on the 7.3 floor (plain static method, array arg — legal on 7.3) and is the single place
the positional order is written down, so downstream 7.3 callers reference keys by name. Piece D builds
its engine `Config` through this factory rather than a hand-rolled positional call.

## 5. Data / config model

None. No schema, no config keys, no compiled-artifact format touched. `resources/compiled/*.php`
(the prebuilt index consumers `require`) is pure array-literal data and is **already valid on 7.3** —
the compiler emits plain arrays. Piece D ships that same prebuilt index and runs the 7.3 runtime
against it; no recompilation-on-host ever happens (compiling stays a CI/author-side step on modern PHP,
but the compiler *sources* are down-levelled too so the whole repo is honestly 7.3 — see §8).

## 6. Security & invariants touched

- **Fingerprint-safety gate stays green.** The gate (`scripts/ci/check-fingerprint-safety.php`)
  inspects the *compiled artifact* for canonical scanner/matcher signature strings; it is
  runtime-version-independent. Nothing in this down-level changes emitted bytes, so the gate is
  unaffected — but it **must run in the new CI matrix** to prove that (§7). Invariant #1 preserved.
- **Rules-update trust chain untouched.** `Rules/SignatureVerifier` (ed25519 via ext-sodium),
  per-file sha256, and `Rules/PhpLiteralValidator` (the pure-array-literal screen run before any
  `require`) are converted syntactically only — no logic change. The `PhpLiteralValidator` uses
  `token_get_all`, whose token constants are stable across 7.3–8.4; **its unit tests are the tripwire**
  and must pass on 7.3. Invariant #3 preserved.
- **Published funnypot-rules artifacts must parse on the 7.3 floor.** The rules-update mechanism fetches
  `.php` rule artifacts that core `require`s after the trust chain passes. Once core runs on 7.3 (Piece
  D's hosts), any artifact carrying 8.x/7.4 syntax would fatal on `require` even though it passed
  signature + literal-validation. **Add a publish-side gate:** the funnypot-rules build must `php -l`
  every emitted `.php` artifact under a **7.3** interpreter before signing/publishing, so a
  down-levelled floor in core is matched by a 7.3-parseable rules feed. (The `PhpLiteralValidator`
  already forbids non-literal constructs; this gate additionally asserts *language-level* 7.3 parsability.)
- **LLM-only-upgrades-a-404 and Content-Type parity** live in the funnypot *app*, not core — untouched.
- **No new attack surface.** De-typing properties moves type enforcement from the engine to docblocks;
  parameter type declarations (the actual input-validation boundary) are retained on every method and
  constructor, so runtime type guarantees at call boundaries are unchanged. The recovered `@var` types
  are recoverable by PHPStan (fast-follow §2).

## 7. Testing strategy

- **CI matrix (`.github/workflows/tests.yml`).** Extend the `phpunit` job matrix from
  `['8.0','8.1','8.2','8.3','8.4']` to `['7.3','7.4','8.0','8.1','8.2','8.3','8.4']`. `7.3` catches
  both the 8.0 *and* 7.4 constructs (it is the true floor); `7.4` guards the 8.0-only conversions in
  isolation. **PHPUnit ^9.5 requires PHP >=7.3**, so no test-framework change is needed (locally
  installed 9.6 confirmed). `setup-php` provisions 7.3 fine.
- **Fingerprint-safety + license gates** keep running (they already run on 8.3 in the recompile/publish
  workflows). Add the fingerprint gate as an explicit step in at least the 7.3 lane, or keep it as its
  own artifact-level job — either way it must be green post-conversion. Invariant #1. **Note:** this
  gate scans a committed static artifact, so its result is version-independent — running it on the 7.3
  lane is a consistency check that the down-level changed no emitted bytes, **not** a "proven on the
  floor" claim (there is nothing floor-specific for it to prove; that phrase applies only to the
  *runtime* acceptance lane below, whose behaviour genuinely is interpreter-dependent).
- **Golden acceptance (real-nuclei).** The `acceptance` job serves the compiled index via `php -S` and
  runs real nuclei. Recommend adding a **7.3 acceptance lane** (or switching the existing one's PHP to
  7.3) so the *runtime* path is proven on the floor, not just unit-tested — this is the strongest proof
  piece D will work. At minimum keep the existing 8.3 acceptance and add 7.3 unit coverage.
- **Parse-check gate.** A cheap `find src tests -name '*.php' -print0 | xargs -0 -n1 php -l` under a
  7.3 container catches any missed 7.4/8.0 syntax before the suite even boots.
- **Dependency-floor check (F).** After regenerating the lock, assert the locked
  `metrictower/funnypot-mainnet-client` release declares a `"php"` constraint satisfied by `>=7.3`, and that
  `composer install` from that lock succeeds on the 7.3 container — the new runtime require must not
  re-raise core's effective floor above 7.3 (§4.3).
- **Anti-regression lint (new, optional).** A tiny CI grep asserting the four converted constructs
  don't creep back in (`fn (`, `??=`, promotion modifiers inside `__construct(`, class-level typed
  props) — cheap insurance that a future 8.x-habit PR doesn't silently re-raise the floor. The
  typed-property type token must be **broad**: match FQCN/namespaced (`Rules\KeyRing`), nullable
  (`?Type`), and union (`A|B`) type tokens, not just `\w+` — a `private Rules\KeyRing $x;` slipping past
  a `\w+`-only regex is exactly the forward-guard blind spot to avoid. The lint's self-test carries a
  **namespaced-type fixture** so this stays covered even though zero such properties exist today.
- **Local dev.** `php vendor/bin/phpunit` on the host stays the workflow; contributors on 8.x see no
  difference. The floor is enforced by CI, not by the dev's local PHP.

## 8. Key decisions I made (confirm at review)

1. **Whole-tree conversion, one honest floor** — convert both the runtime *and* the `Compiler/` subtree
   (and `tests/`) to 7.3, rather than a "runtime-only sub-package with a 7.3 floor while the compiler
   stays 8.x." Rationale: PSR-4 lazy-loads, but the compiler unit tests *do* autoload compiler classes,
   so a split floor would make the 7.3 CI lane either fail or require carving the compiler out of the
   suite — fragile. The transforms are identical mechanical moves everywhere; one `>=7.3` that is
   actually true beats a split floor that needs constant policing. (The compiler still *executes*
   author-side on modern PHP; down-levelling its source costs nothing at author time.)
2. **De-type properties into `@var` docblocks, keep parameter types.** Types stay on every method/
   constructor *parameter* (the real validation boundary, legal on 7.3); only the *property*
   declarations lose their inline type and gain a `@var`. This preserves the runtime type guarantees
   that matter and keeps the types machine-readable for a fast-follow PHPStan pass.
3. **Floor = 7.3, not lower.** Driven by PHPUnit ^9 (`>=7.3`) and the realistic old-WordPress floor for
   piece D; 7.3 also keeps flexible heredoc and trailing-comma-in-calls, which the code uses.
4. **No dev-dependency downgrades.** Verified every `require-dev` package already supports 7.3, so the
   toolchain is unchanged (PHPUnit stays ^9.5).
5. **`symfony/polyfill-php80` recommended but currently a no-op.** Zero 8.0 runtime functions are in
   use, so I recommend adding it purely as a forward-guard (with the anti-regression lint as backup),
   not because current code needs it. Flag for confirm: add the dep, or stay dependency-light and rely
   on the lint alone. I lean *add it* (tiny, no fingerprint risk).
6. **Add a 7.3 real-nuclei acceptance lane**, not just 7.3 unit tests — the runtime path is what piece D
   depends on, so prove it on the floor.
7. **Mechanical, with one additive API.** No behaviour change and no *changed* signature rides along;
   the compiled-artifact format and every existing public signature are byte-identical after conversion.
   The sole addition is the `Config::fromArray()` factory (§4.4, M15) — a new method, breaking nothing.

## 9. Dependencies on other pieces

- **Piece D (honeypot-wordpress) hard-depends on this.** D cannot ship until core parses and runs on
  PHP 7.x; C is its explicit prerequisite. D should be planned to consume core **after** C merges and a
  7.3-tagged core release exists. D builds its engine `Config` through the **`Config` array/builder
  factory** C exposes (§4.4, M15), not a hand-rolled positional constructor call.
- **Piece B (report-to-mainnet) relocates its reporter to `metrictower/funnypot-mainnet-client` (F, supersedes
  D9).** B's `MainnetReporter` becomes `Funnypot\Mainnet\Reporter` in the standalone package, not
  `Funnypot\Report\*` in core — so **no `src/Report/` tree ever lands in core** and there is nothing for
  C to convert or police. The package owns its own PHP `>=7.3` CI lane, so B and C are policed by
  separate gates in separate repos. C's only tie to B is the runtime `require` on `mainnet-client`
  (§2, §4.3), which must resolve on the 7.3 floor. The earlier D9 "fold `src/Report/` into C's 7.3
  matrix" arrangement is **dropped**; so is the older "B stays app-side, no conflict" claim it replaced.
- **Piece E (honeypot-laravel)** is independent of C for its *floor* (Laravel hosts run 8.x), but their
  **file scopes can collide (D9).** If E extracts `src/Laravel/*` into its own package, those files
  leave core and are **excluded from C's conversion scope** — C must not down-level files E deletes.
  Whichever lands first (E's extraction or C's conversion of the bridge) sets C's inventory counts;
  sequence the two explicitly rather than asserting independence. Otherwise, a 7.3-clean core remains a
  strict superset of what E needs and imposes no additional floor constraint on E.
- **The funnypot app** must **not** lower its own floor — it stays `"php": ">=8.0"`. Confirm at review
  that the app's `composer.lock` still resolves after `composer update metrictower/funnypot-core`
  against the widened core constraint (it must, since `>=8.0 ∩ >=7.3 = >=8.0`).
- **No dependency on A1 (mainnet-api) or A2 (mainnet-web).**

---

## Review resolutions applied (2026-08-19)

- **BL1** — §3: corrected the "all dev deps already 7.3-compatible" claim. Called out that the
  constraint is `^5.4 || ^6.0` and the lock pins symfony/yaml **v6.4.43** (`php>=8.1`), which breaks the
  7.3 lane; specified the fix — narrow require-dev to `"symfony/yaml": "^5.4"` (or add
  `config.platform.php: "7.3"`) and regenerate the lock, with a Phase-7 assertion that the lock is
  5.4.x. §4.3: added the `require-dev` narrowing to the composer.json diff.
- **D9** — §2: folded B's `src/Report/` tree into C's 7.3 matrix (B authors 7.3-clean, C's one gate
  polices it); required the 7.3 verification container to carry `pdo_sqlite` + `curl` + `sodium` so
  conditional tests run, not skip; added the rule that `src/Laravel/*` is excluded from C's scope if E
  extracts it. §9: rewrote the B and E dependency bullets accordingly and **dropped** the "B stays
  app-side / no conflict" claim. *(The `src/Report/`-fold portion is later reverted by F below — the
  reporter leaves core entirely; the `src/Laravel/*` exclusion and the `sodium` container requirement
  for the rules trust chain stand.)*
- **F relocation** (decision F, `funnypot-mainnet/docs/2026-08-19-program-decisions.md`) — B's reporter
  relocates from `funnypot-core/src/Report/` into the new standalone `metrictower/funnypot-mainnet-client`
  package (`Funnypot\Mainnet\Reporter`), which carries its own PHP `>=7.3` CI. §2: **removed `src/Report/`
  from C's conversion scope** (it never lands in core), reverting the D9 fold; added that `funnypot-core`
  gains a runtime `require` on `metrictower/funnypot-mainnet-client` and that the require **must resolve on the
  7.3 floor**. §3: noted the new runtime require in the stack. §4.3: added `metrictower/funnypot-mainnet-client`
  to the composer `require` diff and a lock-resolution-on-7.3 check. §7: added a dependency-floor check
  asserting the locked `mainnet-client` satisfies `>=7.3`. §9: rewrote the Piece B dependency bullet —
  no `src/Report/` in core; C's only tie to B is the 7.3-resolvable require. C's construct inventory
  (promotion / typed props / arrow-fns / `??=`) is unchanged apart from dropping the `src/Report/`
  references.
- **M15** — §2 + new §4.4: added a 7.3-callable `Config` array/builder factory (`Config::fromArray()`)
  so 7.3 consumers (Piece D) aren't pinned to the ~20-param promoted constructor's positional order;
  §9 notes D builds its engine `Config` through it.
- **Nit (arrow-fn count)** — §4.1 table and §4.2.c: arrow-fn file count `13 → 12` (15 sites unchanged).
- **Nit (Config params)** — §4.2.a: `Config.php` promoted params `23 → 20` (§4.4 uses 20 throughout).
- **Nit (lint regex)** — §7: broadened the anti-regression typed-prop lint to match FQCN/namespaced,
  nullable, and union type tokens (not just `\w+`), and added a namespaced-type fixture to its self-test.
- **Nit ("proven on the floor")** — §7: dropped the "proven on the floor" framing for the
  fingerprint-safety gate (it scans a static, version-independent artifact); kept the phrase only for
  the runtime acceptance lane, which is genuinely interpreter-dependent.
- **Nit (rules artifacts on 7.3)** — §6: added a publish-side gate requiring every published
  funnypot-rules `.php` artifact to `php -l` clean under a 7.3 interpreter before signing/publishing.
