<?php

/**
 * EXAMPLE — send Laravel 404s to funnypot.
 *
 * This is a copy-paste reference, not autoloaded code. It shows the two ways to route
 * unmatched requests (404s) into the honeypot. Start with detect-only, watch your logs,
 * then turn respond mode on.
 *
 * The Laravel service provider (Funnypot\Laravel\FunnypotServiceProvider) is
 * auto-discovered, binds Funnypot\Engine into the container from config/funnypot.php,
 * and registers `php artisan funnypot:update`.
 *
 *   php artisan vendor:publish --tag=funnypot-config
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// 1. config/funnypot.php  (published; defaults are INERT — detect only)
// ---------------------------------------------------------------------------

return [
    // 'off' | 'detect' | 'respond'. Ship 'detect' first: it only signals, never
    // writes a fake to the wire. Flip to 'respond' once you trust the gate.
    'mode' => env('FUNNYPOT_MODE', 'detect'),

    // Your suspicion predicate. respond() serves nothing unless this returns true,
    // so ordinary 404s from real users are never given a fake. Wire it to your own
    // abuse score / reputation / rate-limit signal.
    'gate' => static function (\Funnypot\RequestContext $r): bool {
        return app('your-abuse-scorer')->looksHostile($r->headers['X-Forwarded-For'] ?? '');
    },

    // minimal | realistic | taunt
    'response_style' => env('FUNNYPOT_STYLE', 'realistic'),

    // Your own scanners (Tenable/nuclei/ASM) must see the REAL posture — never a fake —
    // so genuine vulnerabilities aren't hidden. Match a shared secret header you inject.
    'trusted_bypass' => static function (\Funnypot\RequestContext $r): bool {
        return hash_equals(env('FUNNYPOT_SCAN_SECRET', ''), $r->headers['X-Scan-Auth'] ?? '');
    },

    // Instant un-poison without a deploy.
    'kill_switch' => static fn (): bool => env('FUNNYPOT_ENABLED', '1') === '0',
];

// ---------------------------------------------------------------------------
// 2. app/Exceptions/Handler.php  — route 404s to funnypot in render()
// ---------------------------------------------------------------------------

use Funnypot\Http\ResponseEmitter;
use Funnypot\Engine;
use Funnypot\RequestContext;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/** @var \Throwable $e */
/** @var \Illuminate\Http\Request $request */
public function render($request, \Throwable $e)
{
    if ($e instanceof NotFoundHttpException) {
        $inverter = app(Engine::class);
        $context = RequestContext::fromGlobals();

        // Signal even when you don't serve — score every scanner probe.
        $detection = $inverter->detect($context);
        if ($detection->matched) {
            logger()->info('scanner probe', [
                'ids' => $detection->templateIds(),
                'severity' => $detection->highestSeverity,
            ]);
        }

        // Honeypot (no-op unless mode=respond and the gate is open).
        $response = $inverter->respond($context);
        if ($response !== null) {
            ResponseEmitter::emit($response);   // http_response_code / header / echo
            exit;
        }
        // else: fall through to your normal 404 view.
    }

    return parent::render($request, $e);
}

// ---------------------------------------------------------------------------
// 3. ALTERNATIVE — global middleware (app/Http/Kernel.php $middleware[])
//      \Funnypot\Laravel\HoneypotMiddleware::class
//    It runs detect(), attaches the Detection as a request attribute, and serves a
//    synthesized response in place of the route when respond() returns one.
// ---------------------------------------------------------------------------
