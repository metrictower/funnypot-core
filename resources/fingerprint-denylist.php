<?php

declare(strict_types=1);

// Substrings and patterns that must NEVER appear in a served response body/header. A hit
// means an upstream detection source's own vocabulary leaked into what funnypot serves back
// to an attacker — the one thing the deception design exists to prevent, because a classifier
// that has fingerprinted ModSecurity/CRS before would recognise it and conclude "this is a
// canned/templated reply" instead of a plausible real response.
//
// Hand-curated and append-only. Consumed by src/Compiler/Crs/FingerprintGuard.php, which
// backs the compile-time lint, the Gate-B witness fold, scripts/ci/check-fingerprint-safety.php,
// and the runtime egress guard. A single denylist governs every path.

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
        // Scanner/OAST vocabulary: a served body echoing a probe framework's own name, or the
        // out-of-band callback domains its templates bake into open-redirect/SSRF/CORS witnesses,
        // tells a scanner its canned reply came from a honeypot (it set its OWN collaborator host).
        'projectdiscovery',
        'interactsh',
        'interact.sh',
        'burpcollaborator',
        'nuclei-templates',
        'oast.pro',
        'oast.live',
        'oast.site',
        'oast.online',
        'oast.fun',
        'oast.me',
        '{{interactsh-url}}',
    ],
    // Regex signatures (given without delimiters; matched case-insensitively).
    'patterns' => [
        // A bare CRS rule id: six digits in the 9xxxxx request-rule range, not part of a
        // longer number. Serving one back would echo CRS's own rule numbering.
        '\b9\d{5}\b',
        // ModSecurity with an underscore/hyphen separator (mod_security, mod-security,
        // mod_security_id …); the bare `ModSecurity` literal misses these variants.
        'mod[_-]?security',
        // Scanner names as whole words. Word-bounded so a random alnum run can never collide
        // (a generated token has no word boundary mid-run); prose like "nucleic" is `\b`-safe.
        '\bnuclei\b',
        '\bwafw00f\b',
        '\bidentywaf\b',
        // The word "honeypot" (and "funnypot") in a served byte is a self-unmasking tell.
        '\b(?:funnypot|honeypot)\b',
    ],
];
