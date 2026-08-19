# funnypot-rules — one-time operator setup

These steps cannot be automated from inside funnypot-core (they create a repo and store secrets),
so they are yours to do once. Until step 4 is done, `RulesUpdater` has **no trusted signer** and
every `rules:update` fails closed — the bundled rules keep serving, so nothing breaks; updates
just don't apply yet.

## What lives where

| File (in this `dist/funnypot-rules/` scaffold)         | Its home                                            |
|--------------------------------------------------------|-----------------------------------------------------|
| `README.md`, `channels.json`, `keygen.sh`              | the new **funnypot-rules** repo root                |
| `.github/workflows/verify-release.yml`                 | **funnypot-rules** `.github/workflows/`             |
| `keys/ed25519.pub` (you create it in step 2)           | **funnypot-rules** `keys/` (out-of-band verify copy)|
| `publish-rules.yml` + `publish-rules-release.php`       | already in **funnypot-core** (they need its artifacts + gate scripts + signing secret) — nothing to move |

The publish workflow deliberately lives in **funnypot-core**, not here: it packages
funnypot-core's own `resources/compiled/**`, re-runs funnypot-core's gate scripts, and reads a
funnypot-core-held signing secret. This scaffold is only the distribution repo's own contents.

## Steps

1. **Create the repo.** `github.com/bobbymaher/funnypot-rules` (public, MIT). Copy this scaffold's
   `README.md`, `channels.json`, and `.github/workflows/verify-release.yml` into it.

2. **Generate the keypair** (needs the PHP sodium extension):

   ```sh
   bash dist/funnypot-rules/keygen.sh 2026-01
   ```

   It prints a PUBLIC key (stdout) and a SECRET key (stderr). Save the public key to
   `funnypot-rules/keys/ed25519.pub` (base64, one line) for the canary and manual verification.

3. **Store the secret** as an Actions secret on **funnypot-core**:
   `FUNNYPOT_RULES_SIGNING_KEY` = the base64 secret key from step 2. Never commit it.
   Also add a fine-grained PAT scoped to **`contents:write` on funnypot-rules only** as
   `FUNNYPOT_RULES_RELEASE_TOKEN`, and set the repo **variable** `FUNNYPOT_RULES_KEY_ID = 2026-01`.

4. **Commit the public key into funnypot-core's trust root.** Add the entry `keygen.sh` printed to
   `funnypot-core/resources/rules-signing-keys.php` (inside the `keys` array) via a normal
   reviewed PR. This is the load-bearing trust step: only after this does any release verify.

5. **Cut the first release.** Merge a `resources/compiled/**` change on funnypot-core `main` (any
   normal template refresh PR) — `publish-rules.yml` fires, re-gates, signs, and uploads the first
   release + the `channels` pointer.

6. **Enable a consumer.** On a honeypot host, point the updater at a data dir and schedule it (see
   `funnypot-core/docs/RULES-UPDATE.md`). Least privilege matters: the data dir is owned by a
   dedicated non-web updater user, `0755`, files `0644`, **read-only to the web user**, outside the
   web root — never `0777`.

## Rotation / revocation

- **Rotate:** re-run `keygen.sh` with a new key-id, commit the new public key with a future
  `valid_from` (old key stays valid, `valid_until: null`), swap the CI secret, retire the old key
  with a `valid_until` in a later PR. Overlapping windows mean no coordinated cutover.
- **Revoke a key:** drop its entry from `rules-signing-keys.php` in a funnypot-core patch release
  (a `composer update` event — deliberately decoupled from the rules channel a compromised key
  could otherwise spoof).
- **Revoke one release:** add its version tag to `channels.json.revoked`.
