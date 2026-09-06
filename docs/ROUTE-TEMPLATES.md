# Route templates

A route template (`templates/route/NNN-<name>.yaml`) dresses one served bundle of the compiled index
with an authored response, or folds a brand-new page into the index. `bin/funnypot compile-routes`
turns the directory into `resources/compiled/funnypot-routes.php` (a frozen, priority-ordered rules
array the runtime `RouteTemplateEmulator` interprets) and, for `new_page` documents, the index fragment
`merge-routes` folds. Rebuild everything with `composer build`; `composer check` is the drift law.

## Two kinds of document

- **Enrich** — dresses a bundle the index already routes to. Declares `match` explicitly and claims
  no path: the index is untouched, only the served body/headers change.
- **New page** — carries a `new_page` block and synthesizes its own bundle (`pid` = the template `id`),
  one route key per listed path. `match` is auto-filled to that pid.

Rule order is first-match-wins across the whole set: `priority` (lower first), then `id`. Choose the
first free `NNN` in the family you are extending; the file prefix is convention, `priority:` is the key.

## `match` (closed axes)

| axis | selects a bundle when |
|---|---|
| `template_needle: [s, …]` | its `pid` equals `s`, or `s` is a substring of any id in its `t[]` |
| `pid: [s, …]` | its `pid` equals `s` exactly |
| `body_word_contains: [s, …]` | any of its body words contains `s` |
| `route_key: [k, …]` | **guard** — the resolved store key equals a `k` exactly (see below) |

The first three are OR selector axes. Selection is by bundle metadata, never by request path: an enrich
on a needle dresses that bundle on every path it appears at, and never a co-tenant bundle on the same
path (bare `/logfile` carries an iSpy bundle and a Spring bundle; `template_needle: [springboot-logfile]`
dresses only the latter). Needles substring-match, so keep an `id` clear of any broader needle already in
the set.

`route_key` is a **conjunctive guard**, not a fourth OR axis: when present, the resolved route key
(`'<METHOD> <path>'`, the exact compiled store key) must equal one entry *and* one of the three axes
must still match. A rule may not be route-key-only. Use it to give ONE path its own body where a single
product bundle appears at many paths — e.g. the `directory-listing` bundle is dressed with a
path-correct `Index of /<path>` per key rather than one shared listing. The key comes only from the
resolved `FakeHandle`, never request bytes, so facade and position-blind synthesis stay byte-identical;
a null key (a direct call / embedded host) never satisfies a guarded rule, so unguarded rules keep
first-match-wins. Format is validated at build time: an uppercase supported method, one space, an
absolute path, no query/fragment/control byte, no duplicates.

## `new_page`

```yaml
new_page:
  method: GET            # default GET
  paths: [/a, /b]        # one route key per path, exact
  status: 200
  severity: high         # the default ceiling is `high`; a `critical` page would never serve
  sig: 0                 # 1 = probe-gated root entry; 0 = always serves
  weight: 20             # optional persona weight against corpus co-tenants
  tags: [...]
  name: '...'
  body_words: [...]      # what the synthesized bundle requires; [] for a binary page
  forbidden: [...]
  typed_headers:         # required header substrings the served response is re-verified against
    Content-Type: [application/json]
```

## `response` — a closed key set

Exactly these keys are allowed; any other key fails the build (it is never silently ignored):

| key | role |
|---|---|
| `headers` | authored header map; directive-checked, static text must be CR/LF/NUL-free |
| `body` | directive text, rendered per request through `DirectiveRenderer` |
| `body_b64` | static binary bytes, base64 at rest (favicons — see `FAVICON-HASH.md`) |
| `binary` | legacy `true` marker forcing `body_b64` handling |
| `binary_generator` | the ID of a built-in binary writer, run at serve time |

**Exactly one of `body`, `body_b64`, `binary_generator` must be present.** `body` is subject to the
closed directive vocabulary and the optional `expect:` marker assertion (rendered at seed 0); the two
binary arms skip the body guards (bytes are not directive text) but their headers are guarded exactly
like a text rule's.

### `binary_generator`

Some binary bodies cannot be authored as static bytes because they must carry the deploy's seeded
persona — a heap dump planting *this* host's credentials. Such a rule names a generator:

```yaml
response:
  headers: { Content-Type: application/octet-stream }
  binary_generator: spring_hprof_v1
```

The contract, end to end:

- **Closed registry.** The value is a bare string that must equal an ID in
  `Funnypot\Core\Response\BinaryBodyGeneratorRegistry::IDS` exactly (no trim, no case folding). A
  mapping, list, class name, callback or argument block is a compile error, and the `response` key set
  is closed so no side channel for arguments exists. A compiled rule therefore stays pure data — a
  string ID — which is what keeps the rules-update channel (require'd PHP) safe.
- **Compiled shape.** `bin => 1` plus `binary_generator => <id>`; the new-page bundle is stamped
  `bin => 1` too, so `ResponseSynthesizer` routes it to the emulator under every style (MINIMAL
  included) and can never emit an empty-body substitute.
- **Serve-time guard.** `RouteTemplateEmulator` resolves the ID, calls the generator under
  `try/catch (Throwable)`, and requires a non-empty result of at most 65 536 bytes
  (`RouteTemplateEmulator::MAX_GENERATED_BODY_BYTES`, inclusive — Config's default `maxBodyBytes`).
  An unknown ID, a throw, an empty result or an oversize one declines: nothing is truncated, no partial
  200 is served, and the host serves its ordinary 404. A lower operator `maxBodyBytes` still applies
  to the complete output downstream.
- **Old-runtime fail-safe.** The compiled `body` of a generator rule is a sentinel that is *not* strict
  base64 (`!<id>`). A runtime that predates generators takes the base64 branch for every bin rule,
  and `base64_decode(…, true)` returning `false` makes it decline to 404 — an empty body would have
  decoded to `''` and served a 200 empty attachment. The current runtime branches on
  `binary_generator` before reading `body`.
- **Gates.** The static fingerprint gate and the seeded-render gate scan only headers for bin rules
  (opaque bytes). A generator's own unit test must therefore run `FingerprintGuard::fromPackage()
  ->scan()` over its rendered output across the seed matrix — nothing else ever scans those bytes.
- **Determinism.** A generator is a pure function of the renderer's seeded directives and the render
  seed: no I/O, clock, request data or CSPRNG. The seeded-render gate's render-twice check covers it
  because the emulator defaults to the built-in registry at every construction site.

Adding a generator: implement `BinaryBodyGenerator`, register it in
`BinaryBodyGeneratorRegistry::default()`, append its ID to `IDS` (append-only — an ID is a rule-artifact
contract), and pin its byte format with a strict independent parser in its test. A new compiled rule
shape ships only in the next **minor** core tag.

#### `spring_hprof_v1`

A compact HotSpot HPROF (`JAVA PROFILE 1.0.2`, 8-byte identifiers) whose heap holds twelve rooted
`java.lang.String` objects (Java 17 compact-string layout, LATIN1 byte arrays, Java-compatible hash)
carrying the persona's `spring.datasource.*` URL/username/password, AWS key pair + region,
`spring.security.user.*`, the JWT signing secret and a credentialed Eureka URL. Structurally complete —
UTF8 / LOAD_CLASS / TRACE records, sticky-class roots, class dumps for Object and String, one
HEAP_DUMP_SEGMENT, HEAP_DUMP_END at EOF — and under 4 KB. Its header timestamp is the same seeded boot
date the Spring logfile decoy prints (both render the one keyed `{{pick:spring-log-date:…}}`).

Residual tells, stated rather than hidden: a live heap is megabytes with thousands of classes, so this
survives structural parsing and `strings`/secret extraction, not a size or histogram comparison. Raw
bytes only (no gzip). The logfile decoy returns the complete bounded body and neither advertises
`Accept-Ranges` nor synthesizes a 206 — the route tier is request-header-blind. The opt-in Eclipse MAT
interop harness is `scripts/dev/hprof/check-mat.sh` (uses a preinstalled MAT; never downloads).

## Other top-level keys

| key | role |
|---|---|
| `taunt` | `{ mode: line \| block \| inline_field, open, close, key }` — the TAUNT-style banner carrier; binary rules ignore it |
| `set_cookie` | bare cookie name; a fresh random session cookie per request (stateful-app pages only) |
| `expect` | substrings the seed-0 render must carry (text rules only) |
| `reflects_input` / `html_safe_captures` | opt-outs of the text/html raw-capture reflection lint |
| `version` | template schema version; must not exceed `SchemaVersion::CURRENT` |

## Directives

The body/header vocabulary is closed (`DirectiveRenderer::KNOWN_PREFIXES`); `{{persona.PATH}}` is a
closed field set (`PersonaIdentity::FIELDS`), and the compiler rejects any unknown directive or field
so a typo can never render as dead literal text. `{{persona.*}}` keys on the deploy identity seed;
`{{pick:KEY:a,b}}` keys on the render seed — two templates that repeat the same `KEY` agree.
