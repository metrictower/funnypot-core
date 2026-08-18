# funnypot-core 🍯

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PHP](https://img.shields.io/badge/php-%3E%3D8.0-777bb3.svg)](composer.json)
[![Runtime](https://img.shields.io/badge/runtime-PHP--only-blue.svg)](#how-it-works)

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
> **[github.com/bobbymaher/funnypot](https://github.com/bobbymaher/funnypot)**.

## What it does

- **Nuclei inversion.** Compiles the upstream [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  corpus and inverts each detection template into a response that satisfies its matcher. From 11,196
  HTTP templates it indexes about 6,300 invertible ones into roughly 5,100 `(method, path)` route
  personas.
- **Attack-class emulators.** Reflects LFI, SQLi, command injection, SSTI, XXE, shellshock, Struts
  OGNL, open redirect, reflected XSS and cloud-IMDS probes on any path, with canned inert markers
  (`root:x:0:0`, `uid=0(root)`).
- **Product and route decoys.** Believable `.git/config`, `.env`, `wp-config`, `phpinfo`, `.htpasswd`,
  `server-status`, SSH keys, SQL dumps, phpMyAdmin and more.
- **Anti-fingerprint.** One coherent product persona per attacker (deterministic, spoof-proof seed)
  instead of an impossible "vulnerable to everything" host. Consistent `X-Powered-By`, tamper-evident
  honeytoken cookie.

## Install

```bash
composer require bobbymaher/funnypot-core
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

### Laravel: send 404s to funnypot

The service provider (`Funnypot\Laravel\FunnypotServiceProvider`) auto-registers. Route your 404 path
through the engine and fall back to your own 404 when funnypot has nothing to say:

```php
// app/Exceptions/Handler.php, render(), on a NotFoundHttpException
use Funnypot\Engine;
use Funnypot\Http\Responder;
use Funnypot\Laravel\LaravelRequestMapper;
use Funnypot\Laravel\LaravelResponseMapper;

$context     = LaravelRequestMapper::map($request);
$synthesized = Responder::forRequest(app(Engine::class), $context);
if ($synthesized !== null) {
    return LaravelResponseMapper::map($synthesized);
}
// else fall through to your normal 404 view
```

The published `config/funnypot.php` defaults to `mode = detect` (inert). Start detect-only, watch the
logs, then set `mode = respond` and supply a `gate`. Full drop-in:
[`examples/laravel-exception-handler.php`](examples/laravel-exception-handler.php); step-by-step
rollout: [`docs/INTEGRATION.md`](docs/INTEGRATION.md). A PSR-15 middleware
(`Funnypot\Http\HoneypotMiddleware`) is available for non-Laravel apps.

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
[`resources/UPSTREAM-LICENSE.md`](resources/UPSTREAM-LICENSE.md).
