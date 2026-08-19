<?php

declare(strict_types=1);

// Substrings and patterns that must NEVER appear in a served response body/header. A hit
// means an upstream detection source's own vocabulary leaked into what funnypot serves back
// to an attacker — the one thing the deception design exists to prevent, because a classifier
// that has fingerprinted ModSecurity/CRS before would recognise it and conclude "this is a
// canned/templated reply" instead of a plausible real response.
//
// Hand-curated and append-only. Consumed by src/Compiler/Crs/FingerprintGuard.php, which
// backs both the compile-time lint and scripts/ci/check-fingerprint-safety.php.

return [
    // Literal signature substrings (case-insensitive match).
    'literals' => [
        'OWASP_CRS',
        'OWASP CRS',
        'ModSecurity',
        'Coraza',
        'libinjection',
        'paranoia-level',
        'inbound_anomaly_score',
        'crs-setup',
        'SecRule',
    ],
    // Regex signatures (given without delimiters; matched case-insensitively).
    'patterns' => [
        // A bare CRS rule id: six digits in the 9xxxxx request-rule range, not part of a
        // longer number. Serving one back would echo CRS's own rule numbering.
        '\b9\d{5}\b',
    ],
];
