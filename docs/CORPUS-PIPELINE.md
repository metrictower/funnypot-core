# Corpus pipeline — provenance, pinning, reproducible rebuild

What produces `resources/compiled/nuclei-index.full.php` (the file the detection engine actually
reads), how its source is pinned, how to rebuild it, and how to prove a rebuild reproduces it.

## Two halves, one command

The committed index is a **merged product**, not a plain `compile`:

| half | inputs | step | provenance |
|---|---|---|---|
| corpus | `<nuclei-templates>/http/*.yaml` at the pinned commit | `funnypot compile` | `upstream_tag` / `upstream_sha` (in the index and the sidecar) + `core_commit` / `php_version` / `built_at` (sidecar only) |
| in-repo | `templates/route` + `templates/generated` (and attack / param / crs for the other artifacts) | `funnypot build` — `compile-ai` → `compile-emulators` → `compile-routes` → `compile-params` → `merge-routes` → `build-manifest` | `source_tree`: a sha256 over exactly the `*.yaml` set each step globbed |

`compile` alone exits 0 and silently drops every folded new-page key — all of `templates/route`
and `templates/generated`, 194 keys at the time of writing. That is why the one full rebuild is:

```bash
composer build-corpus                          # == php -d memory_limit=2G bin/funnypot build-corpus
composer build-corpus -- /path/to/checkout     # explicit checkout root
```

`build-corpus` = pin check → `compile <checkout>/http` → `build`, then prints the upstream
revision, the compiler record, the sha256 and the route-key delta (`before -> after (±n)`).

**Editing `resources/ambient-paths.php` needs a full `build-corpus`, not just `build`.** The
ambient stamp (`amb=1`, the AMBIENT classification) is written on BOTH halves from that one list
(`Compiler\AmbientPaths`): the corpus half in `compile`, the fold half in `merge-routes`. `build`
alone re-runs only the in-repo half, so a list edit followed by `build` restamps the folded bundles
but leaves the corpus bundles at the same key on their old stamp — a mixed-stamp key that classifies
SCANNER_PROBE (the safe direction) until `build-corpus` recompiles the corpus half. Two artifact
tests catch that stale state (`CompiledIndexSmokeTest::test_no_route_key_has_mixed_ambient_stamps`
and `test_folded_bundles_in_the_index_match_the_committed_fragment`).

## The pin

`resources/compiled/manifest.json` → `upstream_sha` **is the pin**: the exact
projectdiscovery/nuclei-templates commit the committed index was compiled from. `upstream_tag` is
`git describe --tags --always` of that checkout — a release tag when built from one, a short sha
otherwise. Both are also embedded in the index's own `manifest`, and `doctor` checks the two copies
agree, so the 6 MB file and its readable sidecar can never describe different sources.

`build-corpus` refuses to compile from:

- a directory that is **not a git checkout** — no revision can be recorded, so the corpus would be
  untraceable (nothing to audit, diff, or rebuild against);
- a checkout that is **not at the pin** — unless `--bump` says the move is deliberate.

Checkout resolution: positional argument → `NUCLEI_TEMPLATES_DIR` → `../nuclei-templates` beside
the package. Give it the checkout **root**; it picks `http/` itself. To materialise the pinned
source:

```bash
git clone https://github.com/projectdiscovery/nuclei-templates ../nuclei-templates
git -C ../nuclei-templates checkout "$(php -r 'echo json_decode(file_get_contents("resources/compiled/manifest.json"))->upstream_sha;')"
```

### `~/nuclei-templates` is scratch, not a source

A `nuclei -update-templates` directory (nuclei's default `~/nuclei-templates`) is a zip-extracted
tree with no git history and therefore no revision. It is the right thing to run nuclei *from*
against the honeypot; it is **not** a compile source, and `build-corpus` refuses it. The canonical
source is a git clone at the pin, as above. Two such trees on one machine can differ by a thousand
templates with nothing to say which one made the artifact — the pin exists so that question always
has an answer.

## Refreshing the corpus (moving the pin)

```bash
git -C ../nuclei-templates fetch --tags
git -C ../nuclei-templates checkout v10.x.y
composer build-corpus -- ../nuclei-templates --bump
```

`--bump` prints `route keys : before -> after (±n)` and `pin moved : old -> new`. Then:

1. review the delta — `git diff --stat resources/compiled`, the route-key count, `skipped.json`;
2. if the count fell, lower `ROUTE_KEY_FLOOR` in `tests/CorpusProvenanceTest.php` **in the same
   commit** — that edit is the reviewable record of accepted coverage loss, and the suite fails
   until it is made;
3. `composer check` and `vendor/bin/phpunit`;
4. commit `resources/compiled` + `templates/generated` + `templates/attack-ai`.

The `update-templates` workflow is exactly this procedure at a release tag (dispatch-only while the
CI pause stands).

## Proving a rebuild reproduces the committed bytes

```bash
composer verify-corpus                         # == bin/funnypot build-corpus --verify
```

Compiles the pinned checkout and folds the **committed** fragment (`funnypot-routes-index.php`,
which the drift gate already proves matches `templates/route` + `templates/generated`) into a
scratch dir, then compares sha256 with the committed index. Exit 0 = byte-identical; exit 1 keeps
the rebuilt copy for diffing. It never writes into the tree, and it refuses an off-pin checkout —
verify never bumps.

Why byte-for-byte is achievable: the index carries no wall-clock stamp (`built_at` lives only in the
sidecar), template globs are `SORT_STRING`, `source_tree` paths are repo-relative, every writer is
atomic, and line endings are pinned to LF by `.gitattributes`. The remaining variable is the PHP
that runs the compile — the law is defined at PHP 8.3's bytes, and `php_version` in the sidecar
records what built the corpus half.

The sidecar is reproducible too. `built_at` is `SOURCE_DATE_EPOCH` when set (the reproducible-builds
convention), else the upstream HEAD's committer date, else wall-clock (only for a dir with no
revision, which `build-corpus` refuses anyway) — always UTC. `core_commit` is the package commit
that ran the compile, suffixed `-dirty` when `src/`, `templates/` or `bin/` had uncommitted changes.
Both read `unknown` on a sidecar that predates the record; the next real `compile` stamps them and
`build` preserves them untouched. The same rule gives `crs-manifest.json` its `built_at`.

## Gates

- **Fingerprint-safety** (`scripts/ci/check-fingerprint-safety.php` + `check-runtime-fingerprint-safety.php`)
  — no served string leaf of any compiled artifact may carry an upstream-detector signature. At
  Gate B a template whose satisfying witness (`bw`/`hw`/`rx`/`th`) would freeze such a tell into the
  served bytes is folded OUT with reason `fp:denylisted-witness` (visible in `skipped.json` and
  `funnypot coverage`) rather than served — precise (only the offending template folds; a clean
  co-template re-partitions), so the regenerated index is clean by construction. The static gate then
  walks every served leaf of the committed artifacts (attack/route/param rules + the nuclei + flat
  route indexes) and the runtime gate re-checks the whole rendered corpus. Because the vocabulary + the
  fold + the regenerated corpus must all land together (the static gate fails on the index otherwise),
  they belong in one regeneration.
- **`funnypot doctor --provenance`** — the sidecar must verify the index: sha256, size,
  `route_keys`, `templates_indexed`, and `upstream_sha` / `upstream_tag` / `source_tree` equal to
  the copies embedded in the index; `upstream_sha` must be a full commit sha (`unknown` is drift).
  `scripts/ci/check-drift.sh` runs it — so `composer check` and the `artifact-law` workflow do too.
  Plain `doctor` runs it after the opcache check and exits 1 on either. `--compiled-dir=PATH`
  points it at another pair.
- **`tests/CorpusProvenanceTest.php`** — the route-key floor, with a self-check that the floor still
  sits above "compile alone" (so it cannot rot into a no-op); the in-repo canaries `/.claude.json`,
  `/secrets.json`, `/api/tags` reached via folded `route-*` bundles; the sidecar contract (pin, field
  order, fingerprint, counts); and the `build-corpus` refusals.
- **`build-corpus --verify`** (`artifact-law` workflow) — shallow-checks-out `nuclei-templates` at the
  embedded pin and recompiles, asserting the committed `nuclei-index.full.php` is byte-identical (sha256)
  to a clean rebuild. Closes the drift class `check-drift` cannot see: `check-drift` only re-folds
  (`build`) + checks provenance, so a compiler change that shifts the compiled index without a fold is
  invisible to it. Pins `core.abbrev` to the committed `upstream_tag` length so the shallow clone's
  `git describe` reproduces the embedded provenance.

## manifest.json fields

| field | written by | meaning |
|---|---|---|
| `upstream_tag`, `upstream_sha` | `compile` | the pin (also embedded in the index) |
| `source_tree` | `merge-routes` | sha256 over `templates/route` + `templates/generated` |
| `templates_seen`, `templates_in`, `templates_indexed`, `route_keys`, `multi_bundle_keys`, `largest_bundle_count`, `persona_cap` | `compile`; the two counts refreshed by `merge-routes` | table sizes — `route_keys` / `templates_indexed` are post-fold |
| `built_at` | `compile` | reproducible stamp (see above); preserved by `build` |
| `core_commit`, `php_version` | `compile` | the compiler that produced the corpus half; preserved by `build` |
| `sha256`, `artifact_bytes` | whichever step wrote the index last | fingerprint of `nuclei-index.full.php` |
| `skipped_count` | `compile` | size of `skipped.json`; preserved by `build` |

## Memory

`compile` OOMs at PHP's default 128M — a failure that looks like a corpus problem and is not. The
composer scripts pass `-d memory_limit=2G`; `build-corpus`, `build` and `doctor` also raise a lower
limit to 1G themselves.
