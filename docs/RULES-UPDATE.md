# Runtime rule updates

Consumers stop running `composer update` for daily/weekly rule changes. A separate
[`funnypot-rules`](https://github.com/metrictower/funnypot-rules) repo distributes **signed** rule
artifacts; `funnypot-core` gains a callable updater (`Funnypot\Rules\RulesUpdater`, a CLI, and a
Laravel command) that fetches and hot-swaps rules at runtime.

Opt-in and inert by default: with no data dir configured, the engine loads only the artifacts
bundled in the package — byte-identical to before this mechanism existed.

## The threat this defends

The compiled artifacts are **`require`d PHP** (`PhpArrayStore::fromFile()` does `require $path`). A
naive auto-update is therefore a **remote-code-execution delivery path**. The design treats it as
one at every layer.

## Trust / verify flow

`RulesUpdater::update()`, in order — **everything below runs before anything goes live**:

1. **flock** the data dir (a second concurrent run no-ops rather than racing).
2. **Resolve the target version** — an explicit pin, or a signed `channels.json` pointer.
3. **Fetch + ed25519-verify the manifest.** The manifest is the signed root; it pins the tarball's
   sha256 and every file's sha256. The signature is checked with
   `sodium_crypto_sign_verify_detached` against a public key **vendored inside funnypot-core**
   (`resources/rules-signing-keys.php`), **never fetched** alongside the artifact. Same ed25519
   primitive funnypot uses for the SSH host key.
4. **No-op** if the manifest version already matches current — before any download.
5. **Anti-downgrade** — refuse a `version_seq` ≤ the installed one (unless `rollback()` is the
   explicit caller). Stops a replay of an older, still-validly-signed release.
6. **Fetch the tarball; sha256 must equal the signed value.** A re-pointed/tampered asset is caught
   here — provenance is by digest, so *where* the bytes came from is not the trust anchor.
7. **Extract to an unreferenced `.partial` dir** on the same filesystem (path-traversal guarded).
8. **Per-file sha256** against the signed manifest — every listed file present, none missing.
9. **PhpLiteralValidator on every `.php`.** Proves the file tokenises to exactly
   `<?php [declare(strict_types=1);] return <array-literal>;` — no calls, no `include`/`require`/
   `eval`, no objects/variables/backticks. *A signature proves who published; this proves the bytes
   cannot execute.* So even a compromised-but-trusted signer cannot ship code.
10. **Fetch-time safety subset** (source-free defence-in-depth):
    - **fingerprint-denylist re-scan** — no upstream-detector signature (`OWASP_CRS`, a bare CRS
      rule id, `ModSecurity`…) may reach a served response.
    - **ReDoS budget** — every incoming regex is run against short adversarial inputs under a tight
      PCRE backtrack budget; a catastrophic (exponential) pattern fails the whole update. There is a
      live `preg_match` on attacker input in `TemplateAttackEmulator`.
    - **anti-blinding floor** — reject a set whose route/template/rule counts collapse below a
      fraction of current. A silent detection-kill is an attack, not an update.
11. **Atomic swap** — promote `.partial` to `releases/<version>/`, then `rename()` the `current`
    symlink onto the new release's `engine/` dir (atomic on POSIX). Then `opcache_invalidate` the
    stable paths and drop `PhpArrayStore`'s in-process cache (a rename alone is not hot under a
    persistent worker). Record the version pin; prune old releases beyond the retention count.

**Fail-safe is structural, not a convention:** every failure path returns *before* step 11, so
`current` is untouched and the engine keeps serving the prior release — or, if never updated, the
bundled floor (`RulesLocator::resolve()` falls back on every load; a dangling `current` self-heals).
There is no code path that blanks the rules.

### What signing does NOT cover (stated plainly)

- A **compromised funnypot-core CI/secret** (the signer going rogue) — only key rotation via a
  reviewed funnypot-core PR mitigates that, after the fact. The fetch-time validators (steps 9–10)
  are why a rogue signature still cannot push executable or blinding content.
- A **well-formed but malicious upstream** template sailing through every automated gate — only the
  human PR review that runs *before every release* defends that; the publish workflow fires only
  after that merge.
- The ReDoS screen catches **exponential** catastrophic backtracking, not merely-expensive
  polynomial patterns (those the runtime already bounds via the 32 KB surface cap + PCRE limit and
  fails safe on).

## Engine seam

Every `fromPackage()` loader routes its path through `Funnypot\Rules\RulesLocator::resolve()`:
`<dataDir>/current/<artifact>` when it exists and reads, else the bundled `resources/compiled/`
copy. Checked on **every** load, not just boot. The two loaders built directly in `Honeypot`'s
constructor (`TemplateAttackEmulator`, and `RouteTemplateSet` via `EmulatorRegistry::default`) pick
up the seam through `fromPackage()`.

The data dir comes from `FUNNYPOT_RULES_DIR`, or `RulesLocator::useDataDir()` (the Laravel provider
calls this from `funnypot.rules.data_dir`). Unset = today's behaviour, zero change for non-adopters.

## Surfaces

**CLI** (standalone / cron):

```bash
funnypot rules:update   [--data-dir=PATH] [--channel=stable] [--version=vX]
funnypot rules:status   [--data-dir=PATH]
funnypot rules:rollback [--data-dir=PATH] [--to=vX]
```

Exit codes: `0` rules are good (updated / already current / rolled back); `1` an update was
attempted and failed (rules unchanged — alert, don't page; the honeypot is up); `2` usage/config.

**PHP API:** `new RulesUpdater($dataDir, $channel, $pinnedVersion, $repoUrl)` →
`update()` / `rollback(?$to)` / `status()`, each returning a value object (never throws).

**Laravel:** `php artisan funnypot:rules-update` (`--rollback`, `--to=`, `--status`). Config block
`funnypot.rules` (`data_dir`, `channel`, `pinned_version`, `repo`, `staleness_alarm_hours`).

## Scheduler wiring (operator adds this)

A package cannot inject into your `Kernel::schedule()`; add one line:

```php
$schedule->command('funnypot:rules-update')
    ->dailyAt('03:' . sprintf('%02d', crc32(gethostname()) % 60)) // per-host jitter: no thundering herd
    ->withoutOverlapping()          // mutex the swap
    ->runInBackground()
    ->onOneServer();                // ONLY if the data dir is a shared mount (EFS/NFS).
                                    // For per-node local disk, DROP this — each node must update its own.
```

**Staleness alarm — non-optional.** A wedged updater silently goes blind. The command prints a
`STALE` warning when the last successful check is older than `staleness_alarm_hours`, and returns
non-zero on a failed update so `->onFailure(...)` fires. Back it with an **external** monitor on
`rules:status` → `checked_at` too, so a cron that stopped running at all is still caught.

## Worker reload

Swapping `current` does not retroactively refresh an already-running php-fpm/RoadRunner worker that
parsed the old index into memory (same limitation a manual redeploy has). The updater invalidates
opcache and drops the in-process cache for the swapping process; fleet-wide, a normal worker recycle
(`pm.max_requests`, a rolling restart, `octane:reload`) picks it up on the next cycle.

## Least privilege (operator responsibility)

The data dir holds `require`d PHP, so a web-writable dir would be a webshell drop-point. Do **not**
use `mkdir 0777`. Intended ownership:

- Dir owned by a **dedicated non-web, no-shell updater user**; `0755`; files `0644`.
- **Read-only to the web/runtime user.**
- **Outside the web root.**
- The updater runs as that user via cron/systemd-timer — never as root or the web user.

The updater itself only ever creates the data dir `0755` (never `0777`).

## Publishing (maintainer)

`funnypot-core`'s `.github/workflows/publish-rules.yml` fires on a push to `main` touching
`resources/compiled/**` — i.e. only after a human merges the refresh PR. It re-runs the two security
gates on the merged commit, then `scripts/ci/publish-rules-release.php` packages `resources/compiled`
into `engine/*`, builds + signs the manifest with the CI-secret ed25519 key, and uploads the release
+ `channels` pointer to `funnypot-rules`. One-time setup (create repo, keygen, store secrets, commit
the public key into the keyring): [`dist/funnypot-rules/SETUP.md`](../dist/funnypot-rules/SETUP.md).
