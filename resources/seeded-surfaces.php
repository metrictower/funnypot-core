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
    // --- FP-0277: canned fleet-constant surfaces converted to per-deploy seeded ---
    // {{canned.passwd}} — the service-account tail (set/order/shells) varies; root:x:0:0 head verbatim.
    'attack:attack-lfi-unix' => 'FP-0277 seed-varied /etc/passwd service-account tail',
    // {{canned.shadow}} — the $6$ salt/hash body + account subset vary; :0:99999:7::: aging verbatim.
    'attack:attack-lfi-shadow' => 'FP-0277 seed-varied /etc/shadow salt/hash body',
    // {{canned.ssh_private_key}} — the 12-line base64 key body varies; OpenSSH envelope verbatim.
    'attack:attack-lfi-sshkey' => 'FP-0277 seed-varied inert SSH key body',
    // {{canned.hostname}} — the whole role-env-NN hostname varies (no cross-fleet marker to pin).
    'attack:attack-lfi-hostname' => 'FP-0277 seed-varied /etc/hostname',
    // {{canned.environ}} — the var order + PWD leaf vary; PATH= / USER= markers verbatim.
    'attack:attack-lfi-environ' => 'FP-0277 seed-varied /proc/self/environ order + PWD',
    // {{canned.group}} — the member subset (coherent with passwd) varies; root:x:0: head verbatim.
    'attack:attack-lfi-group' => 'FP-0277 seed-varied /etc/group member set',
];
