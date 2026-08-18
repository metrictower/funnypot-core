# Integrating with iCabbiTools

Documentation only. Nothing here is applied. This describes exactly how the
`iCabbiTools` Laravel 8 app (the repo this package's monorepo lives in) would
consume `bobbymaher/funnypot`, using its own existing honeypot pieces
(`App\Http\Controllers\HoneyPotController`, `App\Http\Middleware\RestrictIPAccess`)
as the fallback path rather than replacing them.

## 1. Require the package via a path repository

In the app's root `composer.json` (not touched by this change):

```json
{
  "repositories": [
    { "type": "path", "url": "packages/funnypot" }
  ],
  "require": {
    "bobbymaher/funnypot": "*"
  }
}
```

`composer require bobbymaher/funnypot` then symlinks the package into
`vendor/bobbymaher/funnypot`. Laravel package auto-discovery picks up
`Funnypot\Laravel\FunnypotServiceProvider` from the
package's `composer.json` `extra.laravel.providers`, so no manual provider
registration is needed in `config/app.php`.

## 2. Publish and configure

```
php artisan vendor:publish --tag=funnypot-config
```

writes `config/funnypot.php`. Add to `.env`:

```
NUCLEI_INVERTER_MODE=detect
NUCLEI_INVERTER_ENABLED=true
```

Ship `mode=detect` first (the package default). Detect never writes to the
wire, so this step is only a signal generator: it lets `Detection` results
flow into the app's existing scoring (`SuspiciousUserMonitoring`,
`IPSecurityService`) with no behavior change to what gets served. `respond`
mode (the honeypot itself) is a deliberate second step behind
`HONEYPOT_ENABLED`/`NUCLEI_INVERTER_ENABLED`, once detect-only has run long
enough to trust it isn't flagging real traffic.

The published config's `gate` closure is where the app plugs in its own
suspicion signal, e.g.:

```php
'gate' => fn ($r) => app(\App\Services\IPSecurityService::class)->isSuspicious($r->headers['X-Forwarded-For'] ?? ''),
```

left `null` (closed) until the app is ready. This is what makes the default
install inert regardless of `mode`.

## 3. Drop-in points

Both integration points call `Funnypot\Http\Responder::forRequest()`, the small
framework-agnostic helper built for exactly this "call me from wherever you
already decide it's a 404 / bad request" shape. They fall back to the app's
existing methods (`funky404()`, `diewithBadResponse()`) on `null`, so current
behavior is preserved byte-for-byte whenever the inverter has nothing to say.

### `app/Exceptions/Handler.php:236-242`

Current code (real 404 path, after the two early middleware calls that
populate `$request->ip`/host):

```php
$honeyPot = new HoneyPotController();
$badUser = $honeyPot->monitor404($request);

if($badUser){
  //$honeyPot->diewithBadResponse($request);
  return $honeyPot->funky404($request); //serve real-looking html instead
}
```

Proposed change (guarded by `HONEYPOT_ENABLED`, `monitor404()`'s existing
bad-user gate untouched):

```php
$honeyPot = new HoneyPotController();
$badUser = $honeyPot->monitor404($request);

if ($badUser) {
    if (env('HONEYPOT_ENABLED', false)) {
        $context = \Funnypot\Laravel\LaravelRequestMapper::map($request);
        $synthesized = \Funnypot\Http\Responder::forRequest(app(\Funnypot\Engine::class), $context);
        if ($synthesized !== null) {
            return \Funnypot\Laravel\LaravelResponseMapper::map($synthesized);
        }
    }

    return $honeyPot->funky404($request); // existing fallback, byte-identical to today
}
```

`respond()` itself is a no-op (`null`) under the shipped `mode=detect` default,
so this drop-in is safe to land before the app ever flips to `respond` mode. It
always falls through to `funky404()` until then. `detect()` still fires
internally either way and its `Detection` can be logged alongside the existing
`monitor404()` scoring once the app wires an `Observer`.

### `app/Http/Middleware/RestrictIPAccess.php:53-54`

Current code (direct-IP-access path):

```php
$hp = new HoneyPotController();
$hp->diewithBadResponse($request);
```

Proposed change, same pattern:

```php
if (env('HONEYPOT_ENABLED', false)) {
    $context = \Funnypot\Laravel\LaravelRequestMapper::map($request);
    $synthesized = \Funnypot\Http\Responder::forRequest(app(\Funnypot\Engine::class), $context);
    if ($synthesized !== null) {
        return \Funnypot\Laravel\LaravelResponseMapper::map($synthesized);
    }
}

$hp = new HoneyPotController();
$hp->diewithBadResponse($request); // existing fallback, byte-identical to today
```

`diewithBadResponse()` calls `die()`, so this middleware currently never
returns past that line; the inverter path returning a Laravel `Response`
instead is a genuine behavior change only once `respond` mode and the gate are
both on. Before that it is exactly today's `diewithBadResponse()`.

## 4. Rollout order (matches SPEC.md §8 decision 2, conservative defaults)

1. Land the composer path-repo require + provider + published config, with
   `NUCLEI_INVERTER_MODE=detect` and `HONEYPOT_ENABLED` unset/false. No
   behavior change; `Detection` data available for logging only.
2. Wire an `Observer` (e.g. bridging into `SuspiciousUserMonitoring`)
   so detect-mode signal augments the existing scoring for a while.
3. Once detect-mode signal is trusted, flip `NUCLEI_INVERTER_MODE=respond` and
   `HONEYPOT_ENABLED=true` behind a canary (single server / percentage), with
   `gate` still requiring the app's own suspicion signal, so the inverter never
   serves a fake on gate-closed traffic.
4. `trustedBypass` should be wired to whatever the org's own ASM/nuclei
   scanning uses (a shared-secret header, per SPEC.md §5, never the spoofable
   User-Agent) so internal scans keep seeing real posture throughout.

None of the above is applied by this change. This file is the plan, not the
patch.
