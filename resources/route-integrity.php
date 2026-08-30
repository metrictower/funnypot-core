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

        // Login decoys reference a secondary product asset/URL that is root-absolute (the correct,
        // base-independent link shape) and byte-faithful to the real product, but that the honeypot
        // does not itself own — so a scanner that follows it gets a plain 404. Owning each target
        // would mean authoring a new per-product asset/page decoy for marginal gain; the emitted
        // bodies stay byte-faithful and the link shape is already correct, so these are accepted.
        array(
            'check' => 'dangling',
            'a' => 'attack-cpsrvd-login',
            'path' => '/cpsess0000000000/styled/basic/css/cjt.css',
            'reason' => 'root-absolute stylesheet href, byte-faithful to cpsrvd (per-session cpsess-scoped asset path); the honeypot serves no such asset so a follow-up GET 404s — correct link shape, owning a per-session CSS asset would be a separate decoy',
        ),
        array(
            'check' => 'dangling',
            'a' => 'attack-jenkins-acegi-login',
            'path' => '/loginError',
            'reason' => 'root-absolute redirect target, byte-faithful to Spring Security authenticationFailureUrl; the honeypot owns no GET /loginError page so a follow-up 404s — correct link shape, a GET /loginError login-error page is a separate decoy',
        ),
        array(
            'check' => 'dangling',
            'a' => 'attack-webmin-session-login',
            'path' => '/unauthenticated/style.css',
            'reason' => 'root-absolute stylesheet href, byte-faithful to miniserv (unauthenticated asset path); the honeypot serves no such asset so a follow-up GET 404s — correct link shape, owning the asset would be a separate decoy',
        ),

        // wp-admin(/) 302s to the byte-faithful auth_redirect() target /wp-login.php; the wordpress
        // attack family owns /wp-login.php by POST only, so a GET navigation resolves to the corpus
        // /wp-login.php page instead. That corpus entry is a WordPress-plugin sample, so the served
        // page is itself a WordPress login — coherent in content, a family-label-only difference.
        // Re-homing the corpus GET key to the wordpress family is a routing/corpus-precedence change
        // that would alter what GET /wp-login.php serves, so it is accepted here rather than forced.
        array(
            'check' => 'dangling',
            'a' => 'attack-wp-admin-redirect',
            'path' => '/wp-login.php',
            'reason' => 'root-absolute redirect target, byte-faithful to auth_redirect(); the GET resolves to the corpus /wp-login.php page (a WordPress-plugin sample serving a WordPress login) — content-coherent, family-label-only leak; re-homing the corpus key would change prod GET /wp-login.php',
        ),
    ),
);
