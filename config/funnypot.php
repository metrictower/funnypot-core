<?php

declare(strict_types=1);

use Funnypot\Response\Style;

/**
 * funnypot config. Defaults are INERT: mode=detect, gate=null (closed),
 * so a plain `composer require` + provider registration does nothing until an
 * app deliberately opts in. Publish with:
 *   php artisan vendor:publish --tag=funnypot-config
 * Full knob reference: SPEC.md §4 "Public API + adapters + updateability".
 */
return [

    // off | detect | respond. detect never writes to the wire; respond is the
    // honeypot itself and must be opted into deliberately per app.
    'mode' => env('NUCLEI_INVERTER_MODE', 'detect'),

    // fn(RequestContext):bool — app suspicion predicate. Left null (closed) by
    // default: respond() always returns null even when mode=respond until the
    // app supplies one, e.g. in a published copy of this file:
    //   'gate' => fn ($r) => app(IPSecurityService::class)->isSuspicious($r),
    'gate' => null,

    // matched-only (fire only on compiled paths — legit-404 guarantee) | any
    'path_scope' => 'matched-only',

    // fn(RequestContext):string — determinism source for persona selection.
    // Left null: the core default is host + seed_salt (spoof-proof, byte-
    // identical on re-scan). Document the two-IP tell (SPEC.md §5) before
    // overriding to a client-IP based seed.
    'persona_seed' => null,

    // coherent (one product persona per attacker+host — the anti-detection
    // default) | greedy (serve every compatible bundle, less stealthy)
    'persona_breadth' => 'coherent',

    // minimal | realistic | taunt — see Response\Style
    'response_style' => Style::MINIMAL,

    // refuse to fabricate anything more severe than this
    'severity_ceiling' => 'high',

    // hard cap on a synthesized body; an oversized response is refused, never truncated
    'max_body_bytes' => 65536,

    // optional tarpit delay (ms), applied by the emitter only, never the core
    'latency_ms' => 0,

    // fn(RequestContext):bool — the org's own scanners/ASM. true => respond()
    // always returns null so genuine scans see real posture. Use a shared-
    // secret header, never nuclei's spoofable User-Agent (SPEC.md §5).
    'trusted_bypass' => null,

    // fn():bool — true disables respond() at runtime (an un-poison switch).
    // Defaults to the NUCLEI_INVERTER_ENABLED env flag.
    'kill_switch' => static fn (): bool => !filter_var(
        env('NUCLEI_INVERTER_ENABLED', true),
        FILTER_VALIDATE_BOOLEAN
    ),

    // fn(RequestContext):bool — root/homepage-class (sig=1) entries fire only
    // when this returns true, so ordinary visitors to "/" never see a fake.
    'probe_signature' => null,

    // per-deploy persona salt so persona differs per site; defaults to the app key.
    'seed_salt' => env('APP_KEY', ''),

    // template ids or tags to never serve
    'exclude' => [],

];
