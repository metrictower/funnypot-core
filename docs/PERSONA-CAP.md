# Persona-cap build spec (Phase 3 / track B)

Grounded in the shipped 5.06 MB `nuclei-index.full.php` (upstream `2ec9141`). The cap's main payoff
is anti-detection and believability, NOT size: `GET /` is only ~14% of the file and the mega-5 paths
~18%; the other ~82% is genuine coverage across 3,600+ real paths + detect metadata and must NOT be
cut. Realistic size after cap ≈ 4.5 MB (keep full detect).

## Where the mass is (measured)
- Multi-bundle keys: 202 (3,587 are singletons). Keys with >20 bundles: 5 only (`GET /` 1252,
  `/index.php` 171, `/login` 115, `/wp-admin/admin-ajax.php` 27, `/login.html` 21).
- `GET /`: 1,252 bundles from ~1,482 templates, 1,242 distinct pids; 1,128 singleton bundles
  (90%); 928 info-only; 205 sev≥medium; 18 critical; 35 non-200 status outliers. 1,227 of its
  template ids appear ONLY at `GET /`.

## 1. Detect/respond split (schema change, backward-compatible)
`routes[key]` becomes `['d' => [full template ids], 'b' => [capped bundles], 'w' => [weights]]`.
- `'d'` (flat full id-list) is emitted only for capped paths; elsewhere detect derives from
  `union(b[*].t)`. So `detect()` keeps FULL coverage while `respond()` is capped.
- `Honeypot::detectionFor` reads `entry['d'] ?? union(b[*].t)`, a one-line change, and it
  MUST stay backward-compatible with the Phase-1 fixture `nuclei-index.php` (no `'d'`, no `'w'`).
- Each kept bundle carries its own integer `'w'` (weight). PersonaSelector reads `bundle['w'] ?? 1`.

## 2. keepScore (compile-time; which bundles survive per capped path)
Applied ONLY to paths with `count(b) > N`. Signals already in the artifact plus a static
prominence table (~40 entries, ~2 KB), the one signal worth adding.

```
PROMINENCE:
  core   (+800): nginx apache apache-tomcat php iis openssh wordpress exchange
  common (+300): drupal joomla jenkins gitlab grafana kibana springboot kubernetes jira
                 confluence phpmyadmin tomcat citrix fortinet vmware redis mongodb elastic
                 rails django struts node
  known  (+80):  any bundle whose templates carry metadata.product AND a cve/vuln tag
  tail   (+10):  everything else (obscure info fingerprints)
META_PIDS (-200): miscellaneous, http-server, discovery, dashboard   # grab-bags, not an identity

keepScore(b):
  identity = per table above (META_PIDS => -200)
  realism  = +1000 if s==200 ; +300 if s in (301,302) ;
             +120 if s in (401,403,500) AND b has a debug/error/auth tag ;
             else -5000            # implausible root identity => effectively dropped
  coverage = 60 * min(tc, 12)      # cap so a tc=29 grab-bag can't dominate
  severity = 40 * band(sev)        # info0..crit4
  cheap    = 25 if (rx empty AND sz empty) else 0
  tagdiv   = 5  * min(distinctTags, 8)
  brittle  = -15 if (anchored-regex OR exact-size) else 0
  return identity+realism+coverage+severity+cheap+tagdiv+brittle

keep = top_N( sortDesc(group.b, keepScore) )
```

## 3. N and which paths
N = 40, applied only where `count(b) > 40`, that is exactly 3 paths (`GET /`, `/index.php`,
`/login`). All other 3,786 keys untouched. N barely affects size (tail is tiny info singletons);
40 is chosen for believability, not bytes.

## 4. Weighted persona selection (runtime; how often each survivor is shown)
Store `'w'` per kept bundle from a coarse popularity tier, DECOUPLED from keepScore:
`core=100, common=30, known=8, tail=2`. Runtime pick stays deterministic + stateless:
```
seed = crc32(personaSeed(r) . seedSalt)          # unchanged
pick = seed % sum(w over candidates)             # candidates already severity/exclude-filtered
walk cumulative w -> bundle
```
Uniform-over-40 would make the host "equally likely anything", itself anomalous in aggregate
scan datasets. Weighted = least-anomalous population distribution. When no `'w'` present (Phase-1
fixture, uncapped singletons), fall back to uniform `crc32(seed) % count`.

## 5. Drop entirely from the SERVED set (~15 at `GET /`)
Implausible-as-a-root-identity: the non-200 / non-redirect / non-debug status outliers
(`101`, `202/203/307` singletons) and any bundle asserting a product and a bare `404`
(self-contradiction). KEEP the debug-`500`/`401` ones (symfony-debug, thinkphp CVE, django, yii);
there the error status IS the vuln signature. Dropped identities still appear in the SPEC §6
exclusion fixture (so the partition is proven), never in the served artifact.

## 6. Cross-path coherence: DEFERRED (Phase 3.5)
`seed % count` picks independently per path, so one scanner can get WordPress at `/` and Jenkins at
`/index.php` (incoherent across a multi-path scan). Fix later: choose a product family once per
attacker from a global weighted table, each path serves the matching family (generic-200 fallback).
Note it in the artifact/manifest as a known residual tell; do NOT block the cap on it.

## Acceptance
- New artifact ≈ 4.5 MB; detect coverage unchanged (full id-lists retained via `'d'`).
- Capped paths have ≤40 bundles; every other path identical to before.
- `GET /` top personas read like a common web host (nginx/WordPress/springboot + a few real
  findings), NOT obscure IoT or an everything-host.
- All existing 50 unit tests + the real-nuclei acceptance stay green (golden templates are on
  uncapped singleton paths, so they are unaffected).
- Add unit tests: keepScore ranking, detect stays full on a capped path, weighted-pick determinism
  + population spread, capped-path bundle count ≤ N.
