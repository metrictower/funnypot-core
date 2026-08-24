<?php

declare(strict_types=1);

/**
 * Route-integrity escape hatches (tracked, append-only). Read by `funnypot lint-routes` and the
 * compile steps. This is the pressure valve for the lint — an intentional collision or override is
 * recorded here with a reason, never by silencing the lint. Three lists:
 *
 *   disabled           Template ids the lint (and the compile steps) skip entirely. Use to drop a
 *                      colliding template at the source. The lint warns on an id that no longer exists.
 *   priority_overrides {id: int} — an effective first-match priority for a claimant, so two same-tier
 *                      same-method claimants get a deterministic winner without editing a generated
 *                      template. The collision check uses the effective priority.
 *   accepted           Specific findings intentionally accepted. Each carries a `reason` so the
 *                      suppression is self-documenting. Shape: {check?, a, b?, path, reason}
 *                      — `a`/`b` are decoy ids, `path` the collision key or the dangling link path.
 */

return array(
    'disabled' => array(),

    'priority_overrides' => array(),

    'accepted' => array(
        // The phpMyAdmin login/gate form action is a relative `index.php`. It is mitigated by the
        // shipped per-panel canonical_slash 301 (102-phpmyadmin-gate.yaml → redirect bare /phpmyadmin
        // to /phpmyadmin/), so a browser resolves it under the owned base /phpmyadmin/index.php.
        // Accepted rather than rewritten to keep the emitted body byte-identical to real phpMyAdmin.
        array(
            'check' => 'dangling',
            'a' => 'attack-phpmyadmin-gate',
            'path' => 'index.php',
            'reason' => 'relative form action mitigated by the canonical_slash 301 (base becomes /phpmyadmin/); resolves to the owned /phpmyadmin/index.php',
        ),
        array(
            'check' => 'dangling',
            'a' => 'attack-phpmyadmin-login',
            'path' => 'index.php',
            'reason' => 'relative form action mitigated by the canonical_slash 301 (base becomes /phpmyadmin/); resolves to the owned /phpmyadmin/index.php',
        ),

        // PRE-EXISTING, UNMITIGATED (phpMyAdmin-class): the phpPgAdmin login body carries relative
        // links (form action `redirect.php`, stylesheet `themes/default/global.css`) with no
        // canonical_slash. Correct fix is a root-absolute action + owned asset path (triage in a
        // follow-up); accepted here to land the lint baseline. Flagged in the FP-0002 report.
        array(
            'check' => 'dangling',
            'a' => 'attack-phppgadmin-login',
            'path' => 'redirect.php',
            'reason' => 'PRE-EXISTING relative form action, no canonical_slash mitigation — triage: make root-absolute (/redirect.php is owned) or add a canonical_slash redirect',
        ),
        array(
            'check' => 'dangling',
            'a' => 'attack-phppgadmin-login',
            'path' => 'themes/default/global.css',
            'reason' => 'PRE-EXISTING relative stylesheet href, no owned target — triage: serve the asset from an owned root-absolute path',
        ),
    ),
);
