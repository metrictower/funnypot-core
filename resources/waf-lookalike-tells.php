<?php

declare(strict_types=1);

// WAF / antibot CHALLENGE-PAGE tells that funnypot must never serve. A honeypot deployed behind or
// beside a real app must not emit anything that reads as a WAF block/challenge interstitial: it both
// breaks the deception (a canned-looking challenge is instantly recognisable) and signals "something
// is watching" — the opposite of a plausible origin response.
//
// This is a SEPARATE, CI/TEST-ONLY denylist from resources/fingerprint-denylist.php. That one backs
// the RUNTIME egress guard (Compiler\Crs\FingerprintGuard, consumed by Honeypot and the emulators,
// fail-closed to 404). Adding these tells there would change runtime behaviour; the ticket forbids
// that. So these live here, consumed ONLY by scripts/ci/check-fingerprint-safety.php and the unit
// test, via Rules\WafLookalikeGuard — never referenced by any src/ runtime path.
//
// Every entry is anchored to challenge-page SHAPE, not a bare word: `403`, `Forbidden`, `Access
// Denied`, plain spinners and plain redirects are legitimate honeypot output and MUST stay green on
// the committed corpus. Prior art is conceptual only (BunkerWeb/Cloudflare/Sucuri/Incapsula/SafeLine
// challenge pages are highly recognisable); no upstream file is vendored.

return [
    // Case-insensitive substrings. Each is specific to a challenge/block interstitial, verified to
    // appear in ZERO served leaves of the current corpus.
    'literals' => [
        // Branded WAF/antibot footers + product names as they appear on their block pages.
        'Web Application Firewall',
        'BunkerWeb',
        'SafeLine',
        'DDoS-Guard',
        'DDoS protection by',
        'Sucuri Website Firewall',
        'Incapsula incident',
        // Cloudflare-style interstitial + block markup/footers.
        'Attention Required',
        'cf-wrapper',
        'cf-error-details',
        'Ray ID',
        // Antibot challenge body phrasing (the "wait while we check your browser" interstitial).
        'Checking your browser',
        'Just a moment',
        'This process is automatic',
        'browser will redirect',
        'enable JavaScript and cookies',
        'Please wait while we',
        // A proof-of-work / bot check that names itself.
        'verify you are human',
        'verifying you are human',
        'proof of work',
        // The recognisable BunkerWeb/antibot CSS spinner class.
        'lds-roller',
    ],
    // Regex signatures (no delimiters, matched case-insensitively). Anchored to challenge-page shape
    // so legitimate 403/redirect/spinner output does not trip them.
    'patterns' => [
        // A JS proof-of-work loop: a COMPARISON that a hash's prefix equals a run of zeros. Anchored
        // to the check shape (startsWith("0000…") / hash.substring(0,4)==="0000…"), NOT mere proximity
        // of a hash name and "0000" — a digest value that happens to begin 0000 is legitimate.
        'startsWith\s*\(\s*["\x27]0{3,}',
        '(?:substring|substr|slice)\s*\([^)]{0,24}\)\s*={2,3}\s*["\x27]0{3,}',
        // A client-side redirect (JS or meta-refresh) INTO a /challenge interstitial — distinct from
        // a plain URL that merely contains the word.
        '(?:location\.href|window\.location|http-equiv=[^>]{0,12}refresh)[^;>]{0,80}challenge',
    ],
];
