# funnypot Architecture Spec

> A reusable PHP package that is the inverse of a nuclei scanner. Given an incoming
> (suspicious) HTTP request, it finds which nuclei template(s) that request probes for and
> either reports the match (detect mode) or builds a response that satisfies those
> templates' matchers (respond mode). A scanner then walks away with a fat, *coherent* vuln
> report, wasting the attacker's time.

Package: `bobbymaher/funnypot` · namespace `Funnypot\` · PHP `>=8.0`
(promoted constructors; no enums / `readonly` / `never`). Runtime require = PHP only;
`symfony/yaml` is a compile-time dev/suggest dep. Ships a prebuilt compiled artifact so
`composer require` needs no build step.

Derived from `projectdiscovery/nuclei-templates` (**MIT**, © 2025 ProjectDiscovery, Inc.).
Verbatim notice ships at `resources/UPSTREAM-LICENSE.md`; compiler stamps the upstream tag+SHA.

---

## 0. Ground truth (validated against the cloned corpus + scanner source)

- 13,569 total templates; **11,196 under `http/`** (target).
- `IsClusterable()` (`nuclei/pkg/protocols/http/cluster.go:19`) =
  `!(payloads || fuzzing || raw || body || unsafe || req-condition || name)`. This is nuclei's
  own clustering gate and doubles as our **request-eligibility filter (Gate A)**.
- Non-invertible subsets (corrected counts): `raw:` = **3,438** (list-item form; not 12),
  `payloads:` 686, `body:` 155, interactsh/OOB **~528** (unfakeable, since the callback goes to
  the scanner's own collaborator), xpath 38.
- Modifiers to honor exactly: `matchers-condition: and` in **7,467** templates (one OUT matcher
  means the whole template is OUT), `negative: true` in **229**, `dsl` in 3,463, `compare_versions`
  in **381** files (302 non-raw, many single-step and *readily* invertible).
- **`MatchStatusCode` is OR-only, exact** ("Status codes don't support AND conditions",
  `match.go`), so **one response has exactly one status line.** This is the physical constraint
  that reshapes the whole design (see §5).
- Post-Gate-A invertible pool is about **6,400 templates, giving ~4,700 `(method,path)` groups**.
  The final IN count is only known after per-witness validation (§6); ship with an auditable
  `skipped.json`.
- Path collisions concentrate the payoff: `/index.php` (213 templates), `/login` (110),
  `/wp-admin/admin-ajax.php` (47), `/wp-login.php` (10+), `GET /` (~2,300).

---

## 1. System overview

An **offline compiler** parses `http/*.yaml`, applies Gate A + a matcher-level invertibility
classifier (§3), groups survivors by `(method, normalized-path)`, partitions each group into
**conflict-free, single-identity persona bundles** (§2), and freezes the result to one
opcache-friendly literal PHP array. At **runtime** the app hands the package a primitive
`RequestContext`; a single hash probe on `"METHOD normalized-path"` either misses (returns
`null`, app serves its own 404) or hits and returns a `Detection` (**detect**) or a synthesized
`(status, headers, body)` (**respond**), choosing one coherent persona per attacker-identity so
re-scans are byte-identical and the host never contradicts itself. All I/O, logging, gating and
banning live in the app via an optional observer; the core is pure. Correctness is certified by
running **real nuclei against a `php -S` server backed by the package**.

---

## 2. Compiled artifact + merge

**Format:** a 100%-literal `return [...]` PHP file frozen by opcache into shared memory
(~0.5 MB / ~4,700 keys). Per-request cost = one COW hash probe; miss = same probe returning
`null` (honeypot traffic is miss-heavy). **No objects/closures/`::class` in the file**; recipe
interpretation is package code, not data. `SqliteStore` behind a `CompiledStore` interface is a
documented escape hatch for memory-constrained hosts only.

**Entry schema** (`schema=1`): every key maps to a list of bundles (singletons have one; collision
heads have several):

```php
'GET /.git/config' => ['b' => [
  [ 's'  => 200,                      // one status (OR-set collapsed at compile)
    'bw' => ['[core]'],              // body substrings that must be present (positive, contains)
    'hw' => [],                      // header-block substrings (all_headers region)
    'nf' => ['<html', '<body'],      // forbidden substrings (negative:true + dsl !contains)
    'sz' => null,                    // size constraint: null | ['eq'=>N] | ['min'=>N]
    'rx' => [],                      // anchored-regex shape constraints (see §3 A1)
    'h'  => ['Content-Type' => 'text/plain'],  // invented headers (Go-canonical key casing)
    'pid'=> 'git',                   // product/stack identity (persona axis, §5)
    'sev'=> 'high',
    'sig'=> 0,                       // 1 = root/homepage-class; respond only on probe signature
    't'  => ['git-config'] ],        // provenance -> detect-mode template ids
]],
```

Sidecars: `manifest.json` (schema, upstream tag+SHA, built_at, groups, skipped count,
sha256), `skipped.json` (`id` to `reason`, coverage audit), `UPSTREAM-LICENSE.md`.

**Merge = conflict-partition (graph coloring), not blind union.** Per group, build each
template's *satisfy-plan* (§3), then color plans into compatible bundles:

```
mergeGroup(templates):
  plans = [satisfyPlan(t) for t in templates]          # classifier output
  bundles = []
  for plan in plans sorted by (status==200 first, desc word-count):
    place into first compatible bundle, else open a new bundle
  return [freeze(b) for b in bundles]

compatible(bundle, plan) is FALSE iff ANY:
  1. plan.status != bundle.status                       # one status line (OR-only)
  2. plan.body_words ∩ bundle.forbidden ≠ ∅
  3. plan.forbidden ∩ bundle.body_words ≠ ∅
  4. size constraints incompatible (eq≠eq, eq vs min>eq, disjoint bands)   # A4
  5. plan is whole-body-exclusive (anchored regex / exact-size) AND bundle non-empty   # A1/A4
  6. plan.product_id conflicts bundle.product_id        # PRODUCT IDENTITY: anti-detection (§5)
```

Satisfying A never breaks B: they land in different bundles and one bundle is served per
attacker, never Frankensteined. Per-bundle body-word cap = 64; mega OR-lists
(`wordpress-plugin-detect`, ~55k) truncate to top-N discriminators (any subset still satisfies).

---

## 3. Inversion engine: IN/OUT classifier + per-matcher satisfaction

**Gate A** (request eligibility): invert `IsClusterable` plus exclude interactsh/OOB,
xpath-only, and **variable-path** templates (`{{paths}}`, `{{param}}` in the request path).

**Gate B** (per-matcher, folded through `matchers-condition`):
`and` means template IN only if every matcher invertible; `or`/default means IN if ≥1 invertible
(satisfy the cheapest, ignore the rest).

| Matcher / modifier | Verdict | Satisfaction |
|---|---|---|
| `status` | EASY | emit one code from the OR-set |
| `size` | EASY | pad matched part to `len==N`; **exact-size means bundle-exclusive** (A4) |
| `word` `condition:and` | EASY | emit all words into the matcher's `part` |
| `word` `condition:or` | EASY | emit one word (cheapest, no anchor) |
| `binary`+`encoding:hex` | EASY | hex-decode at build, emit raw bytes |
| `case-insensitive` | EASY | emit lowercase form |
| `regex` (unanchored, simple) | MED | build-time witness, **validated against Go RE2** (`FindAllString≠∅`), stored as synthetic word |
| **`regex` anchored `^…$`/`$`** | MED+shape | **whole-body-exclusive** constraint, NOT a free word (A1); see `compatible()` rule 5 |
| `dsl` (whitelist) | SUBSET | `status_code==N`, `contains[/tolower]/(body|all_headers,'x')`, `!contains` maps to forbidden, `contains_all/any`, `len(x) ==/>/< N`, `startswith/endswith`, `&&`/`||` |
| **single-step `compare_versions`** | INVERT | emit a boundary-satisfying version into the extracted slot (302 candidates, do NOT blanket-fold) |
| `part: header` / `all` | routed | matches `all_headers` = `HeadersToString` (`\n`-joined, **Go-canonical keys**, **no status line**). Emit canonical casing; **fold any header/all matcher whose literal is a status-line token** (A3) |
| `dsl` `_py(`/`md5`/`hmac`/`regex(`/arithmetic-on-vars, xpath, favicon, OOB | OUT | fold |

**Mandatory classifier screens (from adversarial review, these gate correctness):**
- **A2, dynamic `{{…}}` literals:** screen every word/regex/dsl literal for `{{…}}`.
  Runtime-resolvable (`{{Hostname}}`, `{{Host}}`) so the synthesizer supports them; everything else
  (`randstr`, `md5`, `{{interactsh…}}`, extracted `{{result}}`) means matcher OUT, so fold. 302
  files affected; without this they compile IN and are dead on the wire under `and`.
- **A1, anchor kind:** tag regex anchors; `$` or `^…$` means whole-body-exclusive (rule 5).
- **B6, intra-template satisfiability:** after building a plan verify `status∩≠∅`,
  `required∩forbidden=∅`, size consistent; a contradiction means fold OUT with a reason.
- **C8, header safety:** compiler asserts every synthesized header name/value matches
  `^[^\r\n\x00]*$` and is length-bounded (also re-checked in the emitter).

Engine emits a solved constraint set per bundle. No regex engine, govaluate, or YAML at
runtime.

---

## 4. Public API + adapters + updateability

```php
interface Engine {
    public function detect(RequestContext $r): Detection;            // never null; Detection::none() on miss
    public function respond(RequestContext $r): ?SynthesizedResponse; // null => app serves its own 404
}
```

DTOs (all promoted-ctor, PHP-8.0-safe):
- `RequestContext(string $method, string $path, string $query='', array $headers=[], ?string $rawBody=null, string $host='', string $scheme='https')`: primitives only; **core never
  parses/reflects `$rawBody`**. `::fromGlobals()` helper.
- `TemplateMatch(string $id, string $severity, array $tags, string $name='')`.
- `Detection(bool $matched, array $matches=[], string $clusterKey='', string $highestSeverity='')` + `isEmpty()`, `templateIds()`, `tags()`, `::none()`.
- `SynthesizedResponse(int $status, array $headers, string $body, Detection $satisfies)`.

**Config knobs** (safe defaults make install inert):

| Knob | Default | Controls |
|---|---|---|
| `mode` | `detect` | `off`/`detect`/`respond` |
| `gate fn(RequestContext):bool` | `fn=>false` | app suspicion predicate; false means respond null |
| `pathScope` | `matched-only` | fire only on compiled paths (legit-404 guarantee) |
| `personaSeed fn(RequestContext):string` | **client-ip + host** (document the two-IP tell, §5) | determinism source; never time |
| `personaBreadth` | `coherent` | `coherent` (one product persona) vs `greedy` |
| `severityCeiling` | `high` | refuse fabricating `critical` RCE/upload-success bodies |
| `maxBodyBytes` | `65536` | hard cap; OUT decided before padding (C9) |
| `latencyMs` | `0` | opt-in tarpit only |
| `trustedBypass fn:bool` | RFC1918 + shared-secret header | checked FIRST; force null for own scanners |
| `killSwitch fn:bool` | `NUCLEI_INVERTER_ENABLED` | runtime disable / un-poison |
| `seedSalt` | `''` (Laravel: `app.key`) | per-deploy persona salt |
| `exclude` | `[]` | template-id/tag deny list |

**App-policy seam:** `Observer { onDetection(...); shouldRespond(...):bool }` +
`NullObserver`. Logging/scoring/banning live in the app's observer, never in core.

**Adapters:** PSR-15 `Http\HoneypotMiddleware`; `Http\Honeypot::forRequest()` pure helper +
`Http\ResponseEmitter::emit()` (the one opt-in side-effect); Laravel bridge (`Laravel\`,
auto-discovered) binding `Engine`, publishing config, registering the update command. Only
`Laravel*Mapper` touch `Illuminate\*`. iCabbiTools drop-ins: `Handler.php:236-242` and
`RestrictIPAccess.php:53-54` become `respond()` calls with existing `funky404()` /
`diewithBadResponse()` as the null fallback.

**Updateability:** `bin/funnypot update [--tag=vX]`: pull nuclei-templates at a **pinned
released tag**, compile, golden test, atomic write (tmp/fsync/rename/opcache-invalidate), then
stamp manifest. Laravel: `php artisan funnypot:update`.

---

## 5. Persona, determinism, anti-detection

**The goal, corrected by HTTP physics.** One response = one status line, so "vulnerable to
*everything at once*" is impossible wherever templates disagree on status/size/product. Forcing
it (two `Server:` headers, impossible status) is itself the honeypot tell. Deliverable
reframed: any single scanner walks away with a fat, coherent, plausible vuln report;
different scan-identities deterministically get different personas so the *population* of
scanners broadly covers the corpus, while no single scanner ever sees a contradiction.
`personaBreadth=greedy` is the escape hatch for users who want raw count over stealth.

**Product-identity bundling (the primary anti-detection fix, review b).** `compatible()` must
split bundles on **product/stack identity** (`pid`, from template `metadata.product`/tags), not
just status/size/server-family. Otherwise WordPress-detect + Jenkins-detect (both 200, no word
conflict) co-bundle, and one `/` response reports WordPress and Jenkins and phpMyAdmin at once,
unmasked on the first multi-template scan. `coherent` = one product persona.

**Determinism (no time term):**
```
seed      = crc32( personaSeed(request) . seedSalt )
bundleIdx = seed % count(entry['b'])                 # stable persona per attacker+host
fieldSeed = crc32( seed . normPath )                 # varies free-zone values per URL, repeatable
```
Constrained bytes (literals, part, status, size, header casing) are fixed; free-zone bytes
(token/nonce values, version slots, whitespace, `Date`/`Server` suffixes) vary by seed and are
checked to never introduce a forbidden substring or a CRLF/NUL (C8). Stateless, so consistent
across horizontally-scaled instances.

**Known residual tells (document, don't hide):** (1) persona varies by client IP. A prober with
two IPs sees the same URL return different vuln-sets; mitigate by seeding on real client IP
behind proxies and/or coarsening. (2) breadth of positive paths (every compiled path answers
200) is a tell independent of persona. Honest value: cost imposition on mass low-effort
scanners, not fooling a determined analyst.

**Mandatory before any respond ships:**
- **Root-path (`sig=1`)**: `GET /` fires only with a probe signature present, never for ordinary
  homepage traffic.
- **`trustedBypass` checked before everything** so the org's own ASM/nuclei sees real posture and
  genuine CVEs aren't buried. Use a shared-secret header, not nuclei's spoofable User-Agent.
- Never reflect attacker input; regex gen build-time only; never deserialize request bodies.

---

## 6. Acceptance test (the only non-circular proof)

Real nuclei (Docker, pinned digest) vs a `php -S` server backed by the package:
`comm` the fired template-ids against `golden.txt`; fail if any expected id is missing.

Corrected test-design (review c):
- **Per-persona sweep**, not one fixed persona: drive `personaSeed` to enumerate bundles per
  path and assert per-persona. "Certified by real nuclei" = "% of claimed templates proven",
  bundle by bundle. A single run only certifies one bundle.
- **Exclusion run:** status-outliers on a path must NOT fire under a different persona (proves
  the partition does real work).
- **Unfakeable-absent:** interactsh templates asserted to NOT fire (`-no-interactsh`).
- **Coverage-rot gate:** CI fails if `manifest.skipped` count jumps > threshold between upstream
  tags, and maintains `expected-in.txt` whose folding-OUT is a build failure (silent rot guard).
- **Two nuclei lanes:** pinned digest (reproducible CI) + floating-latest (allowed to fail,
  alerts on nuclei-semantic drift; the fidelity target is the nuclei the *attacker* runs).
- Pure-unit lane (classifier, normalizer, merge, witness-gen) runs framework-free on host PHP.

---

## 7. Phased build plan (revised per review d, smaller first slice)

**Phase 1: detect-only vertical slice, word+status singletons, NO Docker.**
Prove the whole flow (compile, normalize, hash-probe, `Detection`) end-to-end on ~5 dead-simple
**singleton** templates that are pure `status + word(part:body)`: no regex, no negatives, no
encoded paths, no collisions (e.g. `.env`/`wpconfig` word exposures, `phpinfo`, `server-status`,
`.git/config`). Detect mode is independently shippable and is the headline value ("this request
is a scanner probe") for any app that only wants gating.
- *Files:* `RequestContext`, `Detection`, `TemplateMatch`; `Engine`/`Honeypot::detect`;
  `Support\PathNormalizer` (byte-identity on raw request-target; only fold trailing slash and
  strip query; do NOT decode/lowercase percent-escapes), `Store\PhpArrayStore` + a hand-written
  index; pure PHPUnit.
- *Proof:* unit tests. Probe hits return the right template ids; misses return `Detection::none()`;
  encoded-traversal + `/%c0` paths route by byte-identity.

**Phase 2: compiler + classifier over the clusterable corpus.** `Compiler\*` (loader, Gate A
filter, cluster builder), `Classifier` (Gate B + A1/A2/B6 screens), per-matcher inverters +
`RegexWitnessGenerator` (validated vs Go RE2), emits `manifest/skipped/UPSTREAM-LICENSE`.
Proof: ~4,700 keys; stratified golden set fires; `skipped.json` reasons audit-clean.

**Phase 3: merge / conflict-partition + persona bundles.** `BundlePartitioner`
(`compatible()` incl. product-identity), `PersonaResolver`, `sig=1` root flagging.
Proof: per-bundle coverage asserted; two seeds give two self-consistent personas; no response
carries two product identities or two `Server:` families.

**Phase 4: respond synthesis + safety gating + modes + observer.** `ResponseSynthesizer`,
`Config`, all knobs, `Observer`. Proof: default `detect` emits zero bytes; `gate=>false`
/ `trustedBypass` / `sig=1`-without-signature return null; `critical` refused; body ≤ cap;
headers CRLF-safe.

**Phase 5: adapters** (PSR-15 + 404 helper + Laravel bridge + `ResponseEmitter`). Proof:
middleware + Laravel feature tests; iCabbiTools-style call falls back to `funky404` on null.

**Phase 6: real-nuclei acceptance + updateability + release.** Docker golden harness
(per-persona + exclusion + unfakeable-absent + skipped-delta + floating lane); `update` command
(atomic + verified); a regressed template must fail the build.

---

## 8. Open decisions for the human (recommendations in **bold**)

1. **Goal reframe, DECIDED 2026-08-16 (Bob): coherent persona is the default.** "Vulnerable to
   everything at once" is physically impossible (one status line); each scanner gets one fat,
   coherent, plausible report and the corpus is covered across the scanner population. `greedy`
   mode stays available as a per-app flag but is NOT the default.
2. **Respond-mode risk defaults:** ship **`mode=detect` + `gate=>false`** so install is inert;
   respond is strictly opt-in per app. Root `/` requires a probe signature; `severityCeiling=high`
   refuses fake-critical bodies. Confirm these conservative defaults.
3. **Prebuilt artifact committed to the repo:** yes (`composer require` works with zero build
   step; ~0.5 MB generated file committed; `update` opt-in). MIT attribution shipped in-artifact.
4. **`compare_versions`:** invert single-step in v1 (302 candidates, readily invertible); fold
   only raw/flow multi-step.
5. **Client-IP persona tell:** accept documented residual (two-IP correlation defeats persona),
   value = mass-scanner cost imposition, not analyst-proof?
