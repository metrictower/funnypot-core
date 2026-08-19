# funnypot-rules

Signed, versioned rule artifacts for [funnypot-core](https://github.com/bobbymaher/funnypot-core).
Consumers pull fresh nuclei/CRS-derived detection rules at runtime — **no `composer update`** —
via `funnypot-core`'s built-in `Funnypot\Rules\RulesUpdater` (CLI: `funnypot rules:update`).

This repo holds **no compiler and no PHP source**. It is a pure distribution surface: its GitHub
Releases carry the compiled artifacts `funnypot-core` already produces, tests, and gates in its
own CI, republished on a faster, composer-independent cadence and signed so a consumer can trust
them without re-deriving them.

## Trust model (read this)

The compiled artifacts are `require`d PHP. A rules-update channel is therefore an
**RCE-delivery path**, and it is defended in depth:

1. **Provenance — ed25519 signature.** Every release's `manifest.json` is signed with a detached
   ed25519 signature. The signing **public key is vendored inside funnypot-core**
   (`resources/rules-signing-keys.php`) and is **never fetched from here** — a poisoned copy of
   this repo cannot supply its own trusted key. The manifest pins the tarball's sha256 and every
   file's sha256, so signing the manifest authenticates the whole release.
2. **Safety — funnypot-core still validates.** A signature proves *who* published, not that the
   bytes are *safe*. Before anything is loaded, `RulesUpdater` re-checks, source-free:
   every `.php` is a pure array literal (`PhpLiteralValidator`, no calls/includes/eval), no
   upstream-detector fingerprint leaks into a response, no regex blows a PCRE backtrack budget,
   and coverage has not collapsed (anti-blinding floor). Any failure keeps the current rules —
   the honeypot never serves empty.
3. **Anti-downgrade + fail-safe swap.** A monotonic `version_seq` refuses an older release; the
   swap is an atomic symlink rename after full verification; rollback is a local, network-free
   swap to a retained prior release.

Verify a release by hand:

```sh
# public key is committed here for out-of-band verification; runtime trust is the copy in funnypot-core
php -r '$pub=base64_decode(trim(file_get_contents("keys/ed25519.pub")));
  var_dump(sodium_crypto_sign_verify_detached(
    file_get_contents("vX.Y.Z.manifest.json.sig"),
    file_get_contents("vX.Y.Z.manifest.json"), $pub));'
```

## Release assets

Each version tag carries three assets; a rolling `channels` release carries the pointer:

```
vX.Y.Z.manifest.json         signed root (schema, version, version_seq, tarball_sha256, per-file sha256)
vX.Y.Z.manifest.json.sig     detached ed25519 signature over the manifest bytes
funnypot-rules-vX.Y.Z.tar.gz engine/{nuclei-index.full,funnypot-attack,funnypot-routes,funnypot-routes-index}.php
channels.json (+ .sig)       { "latest": "vX.Y.Z", "stable": "...", "revoked": [] }
```

## How releases are cut

`funnypot-core`'s `publish-rules.yml` fires on a push to its `main` that touches
`resources/compiled/**` — i.e. **only after a human merges** the PR that `update-templates.yml` /
`update-crs.yml` opened. It re-runs the two security gates on the merged commit, packages +
signs, and uploads here. Publishing after human merge is deliberately slower than "straight off
green CI" so the fast update path never bypasses the review the slow composer path already had.

See [SETUP.md](SETUP.md) for the one-time operator steps.
