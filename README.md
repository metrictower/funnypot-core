# funnypot-core 🍯

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777bb3.svg)](composer.json)
[![Runtime](https://img.shields.io/badge/runtime-PHP--only-blue.svg)](#how-it-works)

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → [funnypot](https://github.com/metrictower/funnypot)
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → [funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress)
> - Embedding the deception/detection **engine** in your own PHP / PSR-15 app → funnypot-core **← you are here**
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → [funnypot-policy](https://github.com/metrictower/funnypot-policy)

**The HTTP deception engine behind funnypot.** It answers a scanner's probe with the fake-vulnerable
response the scanner was fishing for. It is the inverse of a [nuclei](https://github.com/projectdiscovery/nuclei)
scan: instead of sending a probe and reading the reply to decide "this host is vulnerable", it reads
an incoming probe and writes the reply that satisfies the scanner's own matcher. The scanner walks
away with a full, coherent, wrong vulnerability report while you log every move.

This is the reusable PHP library. Drop it into any Laravel or PSR-15 app and its 404s start answering
scanners with believable decoys. Runtime is pure PHP: no YAML, no extensions, no network. It is inert
by default (detect only); respond mode is opt-in and gated by your own suspicion signal.

> Want to **run** a honeypot, not embed one? The standalone app builds on this package and adds a live
> dashboard, a pure-PHP SSH server, a fake shell, and 18 TCP service emulators:
> **[github.com/metrictower/funnypot](https://github.com/metrictower/funnypot)**.

## What it does

- **Nuclei inversion.** Compiles the upstream [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  corpus and inverts each detection template into a response that satisfies its matcher. From 11,196
  HTTP templates it indexes about 6,300 invertible ones into roughly 5,100 `(method, path)` route
  personas.
- **Attack-class emulators.** Reflects LFI, SQLi, command injection, SSTI, XXE, shellshock, Struts
  OGNL, open redirect, reflected XSS and cloud-IMDS probes on any path, with canned inert markers
  (`root:x:0:0`, `uid=0(root)`).
- **CRS-broadened coverage.** Recall for the generic attack classes (SQLi/XSS/LFI/RCE) is widened
  from the upstream [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset): its portable
  PL1 rules are aggregated into one broadened match per class, behind funnypot's SAME response
  archetype. It never invents a per-rule response and never touches the nuclei corpus — see
  [`docs/CRS.md`](docs/CRS.md).
- **Product and route decoys.** Believable `.git/config`, `.env`, `wp-config`, `phpinfo`, `.htpasswd`,
  `server-status`, SSH keys, SQL dumps, phpMyAdmin and more. Data-bearing decoys draw people and records
  from a shared seeded generator (`Support\Fake`, exposed to templates as `{{fake.person.*}}` directives),
  so rows are coherent per deployment rather than repeated `jdoe`/`example.com` placeholders.
- **Anti-fingerprint.** One coherent product persona per attacker (deterministic, spoof-proof seed)
  instead of an impossible "vulnerable to everything" host. Consistent `X-Powered-By`, tamper-evident
  honeytoken cookie.
- **AI-API recon surface.** A fake Ollama + OpenAI/Anthropic-shaped model API — `/api/tags`,
  `/api/version`, `/api/ps`, `/api/show`, header-branched `/v1/models` — plus a buffered floor on
  the four chat endpoints. One shared model catalog is the single source of truth for every body.

## Install

```bash
composer require metrictower/funnypot-core
```

## Detect mode (always safe)

Detect never writes to the wire. It just tells you a request is a known scanner probe:

```php
use Funnypot\Honeypot;
use Funnypot\RequestContext;

$funnypot = Honeypot::default();                       // inert: detect-only, gate closed

$detection = $funnypot->detect(RequestContext::fromGlobals());
if ($detection->matched) {
    logScannerProbe($detection->templateIds(), $detection->highestSeverity, $detection->tags());
}
```

## Respond mode (opt-in, gated)

```php
use Funnypot\Config;
use Funnypot\Honeypot;
use Funnypot\RequestContext;
use Funnypot\Http\ResponseEmitter;

$funnypot = Honeypot::default(new Config(
    mode: 'respond',
    gate: fn (RequestContext $r) => isSuspicious($r),   // your suspicion predicate; null = closed
    responseStyle: 'realistic',                          // minimal | realistic | taunt
    attackEmulation: true,                               // also reflect LFI/SQLi and friends
));

$response = $funnypot->respond(RequestContext::fromGlobals());
if ($response !== null) {
    ResponseEmitter::emit($response);   // a matched probe gets an inert fake
    exit;
}
// nothing matched: serve your normal 404
```

### Using Laravel?

Use **[funnypot-laravel](https://github.com/metrictower/funnypot-laravel)**
(`composer require metrictower/funnypot-laravel`) — the ServiceProvider + middleware drop-in. This
repo is the framework-agnostic engine.

### Any other framework (PSR-15)

Wire the engine directly. A PSR-15 middleware (`Funnypot\Http\HoneypotMiddleware`) sends matched
probes an inert fake and passes everything else through, so your app serves its own 404 on a miss.
Start detect-only, watch the logs, then set `mode = respond` and supply a `gate`. Step-by-step
rollout: [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Response styles

Set at init with `responseStyle`:

| Style | What the attacker gets |
|---|---|
| `minimal` | Just the tokens the matcher needs. Smallest. The default. |
| `realistic` | A believable fake: a full `.git/config`, a plausible `.env`, a real XML-RPC `methodResponse`. All values inert. |
| `taunt` | Still satisfies the scanner, and carries a visible "honeypot, your scan was logged" marker. |

Rich content is validated against the matcher before use. If a richer body would not satisfy the
scanner it falls back to minimal, so richness can never break the guarantee.

## How it works

Templates are compiled once, at build time, into frozen PHP arrays (`resources/compiled/*.php`). The
app loads them into opcache and serves with a single O(1) lookup. A miss returns `null` so your app
serves its own 404. `symfony/yaml` is only needed by the compiler (`bin/funnypot compile`), which CI
runs weekly against the latest nuclei-templates release. See [`SPEC.md`](SPEC.md) and
[`docs/PERSONA-CAP.md`](docs/PERSONA-CAP.md).

### Response precedence

`respond()` decides what to serve in a fixed order — an earlier tier always wins:

1. **Nuclei-exact (tier 1).** The request routes to a compiled nuclei template or route decoy →
   a byte-exact response derived from what that scanner probes for.
2. **CRS-generic / attack-class (tier 2).** No route matched → `TemplateAttackEmulator` emulates a
   generic attack class (hand-authored rules first, then the CRS-broadened alternation) from a
   hand-authored response archetype.
3. **LLM fake, then plain 404 (tiers 3–4, app layer).**

So a request matching BOTH a nuclei template AND a CRS attack class always gets the nuclei-exact
response — **nuclei-exact beats CRS-generic**. CRS is a coverage multiplier for tier 2, never a
tier-1 source. Full detail, and how to regenerate (`bin/funnypot compile-crs`), in
[`docs/CRS.md`](docs/CRS.md).

**Path ownership override.** A request-blind tier-1 decoy is the *right* answer for most paths, but a
few paths deserve a request-*aware* emulator that dispatches on the request body — a WordPress
`xmlrpc.php` that parses the `methodCall`, a panel login that answers a brute-force attempt. Such a
rule declares `owns_path:` in its template; for those paths the request-aware attack tier is consulted
**before** the static tier-1 entry, and a match wins. Critically, a rule *decline* falls straight
through to the static decoy — so ownership only ever *upgrades* a served path, never removes coverage,
and it sits after the "never shadow a live host route" guard so a real endpoint is untouched. This is
how bare `/xmlrpc.php` and the credential oracles serve request-aware responses even though a static
decoy also keys those paths.

### AI-API recon surface

The same owns_path override backs a fake AI-inference API: Ollama `/api/tags`, `/api/version`,
`/api/ps`, and a per-model `/api/show` (POST), plus a header-branched `GET /v1/models` — no
`anthropic-version` header gets the OpenAI list shape, its presence switches to the Anthropic shape.
A buffered ("non-streaming") floor answers the four chat paths (`/api/chat`, `/api/generate`,
`/v1/chat/completions`, `/v1/messages`) with a static, deliberately-wrong answer and the request's
own model echoed back; the echo is capture-bounded so a malformed model value can never break the
served JSON. `/api/tags` and `/api/ps` also carry a heavy-weighted tier-1 route decoy, so the AI
persona still wins the rare corpus-template collision even where owns_path isn't in play.

Every body is `json_encode()` of a projection from `resources/ai/model-catalog.php`, read through
`Funnypot\Ai\ModelCatalog` — one source of truth for both the route- and attack-tier copies, so
there's nothing to hand-sync. `bin/funnypot compile-ai` regenerates the templates from the catalog
(route templates into `templates/generated/`, owns_path rules into `templates/attack-ai/`); re-run
it after a catalog change, then rebuild in order: `compile-ai` → `compile-routes` → `merge-routes` →
`compile-emulators` (`merge-routes` is idempotent by pid, so re-folding never duplicates a route; a
full deterministic rebuild starts from a base `compile`).

The interactive streaming chat and the actual LLM live in the funnypot **app**, not here — this
package only floors the buffered, non-streaming chat shapes, so those four paths still answer
believably when the app's LLM is off.

## Runtime rule updates (no composer update)

Rules move roughly weekly (nuclei-templates tags, CRS releases). Instead of a `composer update`
per change, a honeypot can fetch **signed** rule releases at runtime and hot-swap them:

```bash
funnypot rules:update  --data-dir=/var/lib/funnypot/rules   # fetch, verify, atomic swap
funnypot rules:status  --data-dir=/var/lib/funnypot/rules
funnypot rules:rollback --data-dir=/var/lib/funnypot/rules  # network-free, to a retained release
```

Laravel: schedule `php artisan funnypot:rules-update` (config block `funnypot.rules`). With no
`data_dir` configured, nothing changes — the engine loads only the bundled artifacts, exactly as
before. Because the compiled artifacts are `require`d PHP, an update is verified in depth before
anything is loaded: an **ed25519 signature** against a public key vendored *inside this package*
(never fetched), a per-file **sha256** cross-check, a **pure-array-literal** proof of every `.php`
(no code can execute on load), a **ReDoS** budget on every regex, a fingerprint-leak re-scan, and
an **anti-blinding** coverage floor. Any failure keeps the current rules — the honeypot never
serves empty. Full mechanism, trust model, and operator runbook:
[`docs/RULES-UPDATE.md`](docs/RULES-UPDATE.md).

## Safety

funnypot can only mislead an attacker, never help one.

- **Emulate output, never execute input.** No `exec` / `eval`, no real filesystem, no outbound socket.
- **Reflect, never harm.** No bombs, no retaliation, no outbound requests. All responses size-capped
  (`maxBodyBytes`, default 64 KB).
- **Never reflects attacker input**, never deserializes a request body. Every synthesized header is
  CRLF/NUL-safe.
- **Inert by default.** A fresh install is detect-only with the gate closed. A layered gate then
  guards respond mode: kill switch, mode, trusted bypass, suspicion gate, severity ceiling, coherent
  persona, body-size cap.
- **Inert fakes only.** `example.com` hosts, RFC-5737 IPs, obviously-fake keys. Never a real secret.
- **Credential oracles never authenticate.** Login endpoints (Webmin, Jenkins, HNAP, and the panel
  logins) answer a brute-force attempt with the real "login failed" — captured only to gate the
  response, never reflected — and have **no success path**: no authenticated session, no auth cookie,
  no code path that could accept a password. Adversarially proven zero-exec.

## Testing

```bash
composer install
vendor/bin/phpunit                 # unit + compiler suite
bash tests/acceptance/run.sh       # real nuclei (Docker) vs a php -S server (golden test)
```

## Licence

MIT, see [LICENSE](LICENSE). Derived in part from
[projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
(MIT, © 2025 ProjectDiscovery, Inc.); the upstream notice is kept at
[`resources/UPSTREAM-LICENSE.md`](resources/UPSTREAM-LICENSE.md). The CRS-broadened attack
templates are derived from [OWASP CoreRuleSet](https://github.com/coreruleset/coreruleset)
(Apache-2.0); its separate notice and statement of changes are at
[`resources/UPSTREAM-LICENSE-CRS.md`](resources/UPSTREAM-LICENSE-CRS.md). A CI license gate
(`scripts/ci/check-license.sh`, SPDX allow-list) enforces this on every upstream refresh.
