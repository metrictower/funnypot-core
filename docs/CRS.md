# OWASP CoreRuleSet as a funnypot attack-template source

funnypot imports the [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset) (CRS) — the
ModSecurity/Coraza generic-attack ruleset — as a SECOND upstream signal source alongside the
nuclei-templates corpus. CRS covers attack **classes** (SQLi, XSS, LFI, RCE) rather than
per-CVE probes, so it is a coverage multiplier for opportunistic attackers. It plugs into
**tier 2 only** and never changes what tier 1 serves.

## Response precedence (the hard rule)

`Honeypot::respond()` serves in a fixed order; an earlier tier always wins:

| Tier | Source | Response |
|------|--------|----------|
| 1 | Nuclei corpus + route decoys (`resolveEntry`) | **Byte-exact**, derived from the scanner's own template |
| 2 | `TemplateAttackEmulator` (`tryAttack`) | Generic attack-**class** emulation from a hand-authored archetype |
| 3–4 | LLM fake, then plain 404 (app layer) | — |

`respond()` calls `resolveEntry()` first and only falls through to `tryAttack()` when **no route
resolves**. CRS lives entirely in tier 2, so:

> A request matching BOTH a nuclei template AND a CRS attack class serves the **nuclei-exact**
> response, never the CRS-generic one. **Nuclei-exact always beats CRS-generic.**

This is proven end to end in `tests/Crs/CrsPrecedenceTest.php`.

## Why CRS is tier 2, not tier 1

A nuclei template carries enough structure to computationally derive a full byte-exact response
that satisfies its matcher — that inversion is the whole nuclei pipeline. A CRS rule has no
response to invert: it only says "if `ARGS` looks like class X, raise the anomaly score". So CRS
supplies the **detection side only**, exactly like funnypot's own hand-authored
`templates/attack/*.yaml` — and it plugs into that same pipeline.

## What is imported

Per attack class (**sqli, xss, lfi, rce** — the classes funnypot already holds a response
archetype for), every portable PL1 CRS rule is aggregated into **one broadened regex
alternation** behind the class's **existing** response archetype. funnypot never emits one
template per CRS rule id and never invents a per-rule response.

- **Operators.** Only `@rx` (plain regex) and `@pmFromFile` (a dictionary → escaped-literal
  alternation) are portable. `@detectSQLi`/`@detectXSS` call the opaque libinjection C library
  and cannot be inverted to a regex — they are dropped and audited.
- **Aggregation.** `@rx` branches (higher signal) sort ahead of `@pmFromFile` literals. The
  combined alternation is `~`-delimiter-safe, `(?J)` for duplicate named groups, and bounded to
  stay under PCRE's compile limit; anything trimmed to fit is recorded.
- **Severity.** CRS `CRITICAL → high`, `ERROR → medium`, `WARNING/NOTICE → low` (respects
  funnypot's default `severityCeiling: high`). Each class also carries an archetype severity
  floor, so fake RCE stays `critical` = **gated by default**, matching funnypot's own posture.
- **Priority.** CRS templates get a high `priority` (950+) so first-match-wins keeps the specific
  hand-authored rules (priority 31–90) ahead of the broad CRS alternation — CRS only widens the
  tail.
- **Provenance tags.** Each CRS template carries `crs` + `crs-plN`, so the operator can tell
  funnypot's own rule from the CRS-broadened one.
- **Skipped, and why.** Everything dropped is written to `resources/skipped-crs.json`: opaque
  operators, higher paranoia levels (PL2–PL4 by default), negated operators, response-side
  rules, and uncombinable backreference patterns.

## Regenerating

```bash
# 1. Fetch a pinned CRS release (never a branch HEAD).
git clone --depth 1 --branch v4.29.0 https://github.com/coreruleset/coreruleset /tmp/crs

# 2. Derive one broadened attack template per class into templates/attack-crs/.
php bin/funnypot compile-crs /tmp/crs/rules --pl=1      # --pl=2 opts into higher paranoia

# 3. Fold them into the runtime emulator index (reads templates/attack + templates/attack-crs).
php bin/funnypot compile-emulators

# 4. Prove it.
vendor/bin/phpunit
php scripts/ci/check-fingerprint-safety.php            # no CRS signature in any served body
bash scripts/ci/check-license.sh /tmp/crs resources/upstream-licenses/coreruleset.LICENSE.md
```

`compile-crs` writes: the per-class templates (`templates/attack-crs/*.yaml`, human-diffable),
`resources/skipped-crs.json` (the audit trail), and `resources/compiled/crs-manifest.json` (the
CRS tag/SHA + kept/skipped counts). This is automated weekly by
[`.github/workflows/update-crs.yml`](../.github/workflows/update-crs.yml), which opens a PR and
never auto-merges.

## Safety gates

- **Fingerprint-safety** (`scripts/ci/check-fingerprint-safety.php`, denylist at
  `resources/fingerprint-denylist.php`). Fails the build if any compiled response body/header
  carries an upstream-detector signature — `OWASP_CRS`, `ModSecurity`, `libinjection`,
  `paranoia-level`, a bare CRS rule id, etc. CRS's `msg`/`logdata` text is never captured by the
  parser, and generated templates never reflect attacker input (`{{match.*}}`/`capture` are
  stripped), so only the attack **class**, never the detector, is ever exposed.
- **License** (`scripts/ci/check-license.sh`, SPDX allow-list at
  `resources/ALLOWED-LICENSES.txt`). CRS is Apache-2.0 (allow-listed). The gate resolves the
  upstream SPDX id, fails on anything off the list, and commits the fetched license text into the
  PR diff. CRS's Apache-2.0 notice + statement of changes is kept **separate** from the nuclei
  MIT notice, at `resources/UPSTREAM-LICENSE-CRS.md`.

## Known limitation

CRS's regexes assume its own transform pipeline ran first (`t:urlDecodeUni`,
`t:htmlEntityDecode`, `t:jsDecode`, …). funnypot's match surface only does raw + one
`rawurldecode()` pass, so a CRS-derived regex has more false negatives on double-encoded /
HTML-entity / JS-escaped obfuscation than CRS itself. This is a recall limitation, not a safety
gap.
