<?php

declare(strict_types=1);

/**
 * The seeded-surface registry for the FP-0276 seeded-render gate (scripts/ci/check-seeded-render.php,
 * check G4). Each entry names a served surface whose RENDERED output MUST differ across deploy seeds
 * (driven by the deploy-seed helper, no per-request/time/CSPRNG input) — that is how the epic's AC1
 * ("the named surface varies per deploy") is machine-checked, and how a regression that silently
 * re-constants a surface is caught.
 *
 * Keys are '<kind>:<rule-id>' (kind ∈ attack|route|param|synth); values are a short human note. The
 * `synth:` kind names an AGGREGATE surface over the whole nuclei index, rendered by the gate's
 * minimal-synth leg (--nuclei) rather than by a single rule. TRACKED and
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
    // --- FP-0278: the decoy surface graph de-fingerprinted (set/order/nouns per deploy) ---
    // {{surface.sitemap}} — the <loc> set + order + noun paths vary; the spine locs stay advertised.
    'route:route-surface-sitemap' => 'FP-0278 seeded surface graph (sitemap subset/order/nouns)',
    // {{surface.disallow}} — the Disallow set + order vary; /admin stays the fixed first line.
    'route:route-surface-robots' => 'FP-0278 seeded surface graph (robots Disallow set/order)',
    // 397 _links resource nouns are seeded (c1/c2/d1/d2), coherent with the docs/sitemap/nav.
    'route:route-surface-root' => 'FP-0278 seeded surface graph (API root index nouns)',
    // 345 /api/v2 endpoint nouns are seeded (c1/c2), coherent with the rest of the graph.
    'route:route-api-v2' => 'FP-0278 seeded surface graph (/api/v2 endpoint nouns)',
    // 400 admin nav links the seeded /admin/<c1>,/admin/<c2> collection nouns.
    'route:route-surface-admin' => 'FP-0278 seeded surface graph (admin nav nouns)',
    // 330 OpenAPI 3.0 (/openapi.json) paths carry the four seeded nouns.
    'route:route-openapi-json' => 'FP-0278 seeded surface graph (OpenAPI 3.0 JSON nouns)',
    // 340 OpenAPI 3.0 (/swagger.json) paths carry the four seeded nouns.
    'route:route-swagger-json-doc' => 'FP-0278 seeded surface graph (Swagger/OpenAPI JSON nouns)',
    // 341 Swagger 2.0 (/v2/api-docs) paths carry the four seeded nouns under basePath /api/v1.
    'route:route-swagger2-apidocs' => 'FP-0278 seeded surface graph (Swagger 2.0 nouns)',
    // 342 OpenAPI 3.0 (/openapi.yaml) paths carry the four seeded nouns.
    'route:route-swagger-yaml-doc' => 'FP-0278 seeded surface graph (OpenAPI YAML nouns)',
    // --- FP-0279: the TIER-2 static attack-class bodies persona-seeded ---
    // {{attack.sqli.*}} — the PHP error frame / offending-token fragment / docroot path+line vary; the
    // 1064 sentence, `SQL syntax` and `' at line 1` markers stay verbatim.
    'attack:attack-sqli' => 'FP-0279 seeded attack-class body (SQLi error frame/near/path)',
    // attack-crs-sqli is a compile-time copy of 50-sqli — the same seeded MySQL error per deploy.
    'attack:attack-crs-sqli' => 'FP-0279 seeded attack-class body (CRS SQLi error frame/near/path)',
    // {{attack.page.*:search}} — the CRS-xss decline page title + copy vary (no scanner marker here).
    'attack:attack-crs-xss' => 'FP-0279 seeded attack-class body (CRS-xss decline page copy)',
    // {{attack.page.*:home}} — the SSTI decline page title + copy vary; 43/45 render one page per deploy.
    'attack:attack-ssti-numeric' => 'FP-0279 seeded attack-class body (SSTI decline page copy)',
    'attack:attack-ssti-multifence' => 'FP-0279 seeded attack-class body (SSTI decline page copy)',
    // (param:param-sqli-differential is NOT registered: the gate renders its persona-varying BASE body
    //  at $r = null, so the breaker variance is proven by the unit test instead — FP-0279 plan §3.)
    // --- FP-0281: the minimal-synth scaffold + witness-header names, seeded per deploy ---
    // The bw word ORDER across all multi-word bundles (aggregate hash). Registering this key also arms
    // the gate's ≥50% multi-word body-order floor (G6) — it is enforced only once this entry exists.
    'synth:minimal-body-order' => 'FP-0281 deploy-seeded bw word order (aggregate over all multi-word minimal-synth bundles)',
    // The synthetic witness-header NAMES actually served (aggregate). Was the fleet-constant X-Detected-N.
    'synth:witness-header-names' => 'FP-0281 deploy-seeded witness-header names (was X-Detected-N)',
];
