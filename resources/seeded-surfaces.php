<?php

declare(strict_types=1);

/**
 * The seeded-surface registry for the FP-0276 seeded-render gate (scripts/ci/check-seeded-render.php,
 * check G4). Each entry names a served surface whose RENDERED output MUST differ across deploy seeds
 * (driven by the deploy-seed helper, no per-request/time/CSPRNG input) — that is how the epic's AC1
 * ("the named surface varies per deploy") is machine-checked, and how a regression that silently
 * re-constants a surface is caught.
 *
 * Keys are '<kind>:<rule-id>' (kind ∈ attack|route|param); values are a short human note. TRACKED and
 * APPEND-ONLY: FP-0277..FP-0284 each append the surface(s) they convert from fleet-constant to
 * per-deploy. The initial entries are surfaces that already vary through {{persona.*}} at a469c71 —
 * the regression baseline the siblings build on. The gate's fleet-constant inventory (informational)
 * is the counterpart: the shrinking list of surfaces still identical at every grid point.
 *
 * @return array<string,string>
 */
return [
    // WordPress config backup: DB name/user and the persona company surface through the render.
    'route:route-wp-config' => 'FP-0276 persona-derived WordPress config credentials',
    // A dotenv exposure: the persona company/domain + fake secrets vary per deploy.
    'route:route-dotenv' => 'FP-0276 persona-derived .env credentials',
    // phpinfo surface carries the deploy persona (company/domain/versions).
    'route:route-phpinfo' => 'FP-0276 persona-derived phpinfo identity',
    // The phpMyAdmin login shell renders {{persona.classPrefix}} + {{persona.phpmyadmin.version}}.
    'attack:attack-phpmyadmin-login' => 'FP-0276 persona-derived phpMyAdmin login identity',
];
