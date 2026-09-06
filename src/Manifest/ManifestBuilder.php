<?php

declare(strict_types=1);

namespace Funnypot\Core\Manifest;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Throwable;

/**
 * Derives the decoy registry manifest from the compiled artifacts (build/CI-time only — never
 * served). Two bands:
 *
 *   Band A — the hand-authored decoys (attack / attack-crs / attack-ai / param / new-page) as full
 *            records: id, tier, family, method-scoped owned routes with provenance, declared
 *            outbound links from a compile-time body scan, severity, tags.
 *   Band B — the large nuclei-inversion corpus, summarized per product family plus a flat
 *            path -> family index (no per-key bodies).
 *
 * Enrichers (content-needle synthesis, not path claimers) are enumerated separately so a reviewer
 * never mistakes a needle for a route.
 *
 * The manifest is inert data: it carries route keys, ids, families and link targets — never a
 * served body — so it is not a fingerprint surface. 7.3-clean (no enums/match/arrow-fns).
 */
final class ManifestBuilder
{
    const SCHEMA = 1;

    /** Deterministic stubs for the one decoy-session skin render (§3.5); never a real deploy secret. */
    const STUB_SEED = 1;
    const STUB_KEY = 'manifest-build-stub-key';

    /**
     * Tags that name an attack class, a role, a paranoia level, or a provenance marker — never a
     * product family. A record's family is the first tag NOT in this set (and not a cve- or crs-
     * prefixed marker); when none qualifies the id is used instead.
     *
     * @var array<string,bool>
     */
    private static $genericTags = array(
        'attack' => true, 'param' => true, 'route' => true, 'crs' => true,
        'rce' => true, 'lfi' => true, 'sqli' => true, 'xss' => true, 'ssti' => true,
        'xxe' => true, 'ognl' => true, 'traversal' => true, 'command-injection' => true,
        'injection' => true, 'php-injection' => true, 'source-disclosure' => true,
        'file-disclosure' => true, 'auth-bypass' => true, 'open-redirect' => true,
        'redirect' => true, 'ssrf' => true, 'memory-leak' => true, 'phpinfo' => true,
        'webshell' => true, 'backdoor' => true, 'exposure' => true, 'appliance' => true,
        'ai-recon' => true, 'panel' => true, 'login' => true, 'mock-auth' => true,
        'credential-oracle' => true, 'iot' => true, 'vuln' => true, 'disclosure' => true,
        'path' => true,
    );

    /** @var array<string,bool> */
    private static $httpMethods = array(
        'GET' => true, 'HEAD' => true, 'POST' => true, 'PUT' => true, 'DELETE' => true,
        'PATCH' => true, 'OPTIONS' => true, 'TRACE' => true, 'CONNECT' => true,
    );

    /**
     * Standard artifact paths under a package root, for the CLI and tests.
     *
     * @return array<string,string>
     */
    public static function defaultPaths(string $root): array
    {
        $base = rtrim($root, '/') . '/resources/compiled/';

        return array(
            'attack' => $base . 'funnypot-attack.php',
            'param' => $base . 'funnypot-param.php',
            'nuclei' => $base . 'nuclei-index.full.php',
            'enrichers' => $base . 'funnypot-routes.php',
        );
    }

    /**
     * Build the two-band manifest.
     *
     * @param array<string,string> $paths keys: attack, param, nuclei, enrichers
     * @return array<string,mixed>
     */
    public function build(array $paths): array
    {
        $attackRules = $this->loadArray($paths['attack'] ?? '');
        $paramIndex = $this->loadArray($paths['param'] ?? '');
        $nuclei = $this->loadArray($paths['nuclei'] ?? '');
        $enricherRules = $this->loadArray($paths['enrichers'] ?? '');

        $bandA = array();
        foreach ($this->attackRecords($attackRules) as $rec) {
            $bandA[] = $rec;
        }
        foreach ($this->paramRecords($paramIndex) as $rec) {
            $bandA[] = $rec;
        }
        foreach ($this->newPageRecords($nuclei) as $rec) {
            $bandA[] = $rec;
        }

        $corpus = $this->corpus($nuclei);
        $enrichers = $this->enrichers($enricherRules);

        return array(
            'schema' => self::SCHEMA,
            'generated_by' => 'funnypot build-manifest',
            'counts' => array(
                'band_a' => count($bandA),
                'corpus_families' => count($corpus['families']),
                'corpus_keys' => count($corpus['index']),
                'enrichers' => count($enrichers),
            ),
            'bandA' => $bandA,
            'corpus' => $corpus,
            'enrichers' => $enrichers,
        );
    }

    /**
     * Band A records for the attack tiers (attack / attack-crs / attack-ai), in first-match
     * (compiled) order.
     *
     * @param array<int,array<string,mixed>> $rules
     * @return array<int,array<string,mixed>>
     */
    private function attackRecords(array $rules): array
    {
        $out = array();
        foreach ($rules as $rule) {
            if (!is_array($rule) || !isset($rule['id'])) {
                continue;
            }
            $id = (string) $rule['id'];
            $tags = $this->stringList($rule['tags'] ?? array());
            $methods = $this->methodSet($rule['match'] ?? array());
            $hasPathAnchor = $this->hasPathCondition($rule['match'] ?? array());

            $owned = array();
            foreach ($this->stringList($rule['owns_path'] ?? array()) as $path) {
                foreach ($methods as $m) {
                    $owned[] = array('method' => $m, 'path' => $path, 'via' => 'owns_path');
                }
            }
            // A path-anchored rule with no owns_path still claims its literal path when the in:path
            // regex reduces to a fixed string — provenance 'match-regex'. (owns_path rules already
            // record the claim, so this only adds the anchor-only case.)
            if ($owned === array()) {
                $literal = $this->literalPathAnchor($rule['match'] ?? array());
                if ($literal !== null) {
                    foreach ($methods as $m) {
                        $owned[] = array('method' => $m, 'path' => $literal, 'via' => 'match-regex');
                    }
                }
            }

            $out[] = array(
                'id' => $id,
                'tier' => $this->attackTier($id),
                'family' => $this->familyFor($tags, $id),
                'owned_routes' => $this->dedupeRoutes($owned),
                'outbound_links' => $this->attackLinks($rule),
                'severity' => (string) ($rule['severity'] ?? $rule['sev'] ?? 'unknown'),
                'tags' => $tags,
                'priority' => isset($rule['priority']) ? (int) $rule['priority'] : null,
                'unanchored' => !$hasPathAnchor,
            );
        }

        return $out;
    }

    /**
     * Band A records for the param tier — one per compiled bucket entry.
     *
     * @param array<string,mixed> $index
     * @return array<int,array<string,mixed>>
     */
    private function paramRecords(array $index): array
    {
        $out = array();
        foreach ((array) ($index['buckets'] ?? array()) as $entries) {
            foreach ((array) $entries as $entry) {
                if (!is_array($entry) || !isset($entry['id'])) {
                    continue;
                }
                $id = (string) $entry['id'];
                $tags = $this->stringList($entry['tags'] ?? array());
                $method = strtoupper((string) ($entry['method'] ?? 'GET'));
                $prefix = $this->literalRegexPrefix((string) ($entry['regex'] ?? ''));

                $owned = array();
                if ($prefix !== '') {
                    $owned[] = array('method' => $method, 'path' => $prefix, 'via' => 'param-bucket');
                }

                $out[] = array(
                    'id' => $id,
                    'tier' => 'param',
                    'family' => $this->familyFor($tags, $id),
                    'owned_routes' => $owned,
                    'outbound_links' => $this->paramLinks($entry),
                    'severity' => (string) ($entry['severity'] ?? $entry['sev'] ?? 'unknown'),
                    'tags' => $tags,
                    'priority' => isset($entry['priority']) ? (int) $entry['priority'] : null,
                    'unanchored' => false,
                );
            }
        }

        return $out;
    }

    /**
     * Band A records for the folded new-page decoys: nuclei-index route keys whose bundle pid is
     * `route-*` (the discriminant candidates() uses). One record per such route key. Bodies are
     * synthesized (not stored in the index), so outbound_links is empty for this tier.
     *
     * @param array<string,mixed> $nuclei
     * @return array<int,array<string,mixed>>
     */
    private function newPageRecords(array $nuclei): array
    {
        $templates = (array) ($nuclei['templates'] ?? array());
        $out = array();
        foreach ((array) ($nuclei['routes'] ?? array()) as $key => $entry) {
            $bundle = $this->firstRoutePidBundle($entry);
            if ($bundle === null) {
                continue;
            }
            list($method, $path) = $this->splitRouteKey((string) $key);
            $templateId = (string) (($bundle['t'][0] ?? '') ?: '');
            $meta = is_array($templates[$templateId] ?? null) ? $templates[$templateId] : array();
            $tags = $this->stringList($meta['tags'] ?? array());
            $family = $this->familyFor($tags, (string) ($bundle['pid'] ?? ''));

            $out[] = array(
                'id' => (string) $key,
                'tier' => 'new-page',
                'family' => $family,
                'owned_routes' => array(array('method' => $method, 'path' => $path, 'via' => 'route-key')),
                'outbound_links' => array(),
                'severity' => (string) ($bundle['sev'] ?? $meta['sev'] ?? 'unknown'),
                'tags' => $tags,
                'priority' => null,
                'unanchored' => false,
            );
        }

        return $out;
    }

    /**
     * Band B — the nuclei corpus summarized. `families` groups corpus keys by product pid;
     * `index` maps every corpus route key to its family (the resolver's target space). Route keys
     * whose only bundles are `route-*` (Band A new-page) are excluded.
     *
     * @param array<string,mixed> $nuclei
     * @return array<string,mixed>
     */
    private function corpus(array $nuclei): array
    {
        $families = array();
        $index = array();
        foreach ((array) ($nuclei['routes'] ?? array()) as $key => $entry) {
            $pids = $this->corpusPids($entry);
            if ($pids === array()) {
                continue;
            }
            list($method, $path) = $this->splitRouteKey((string) $key);
            $first = $pids[0];
            $index[(string) $key] = array('family' => $first, 'pid' => $first, 'tier' => 'exact-route');
            foreach ($pids as $pid) {
                if (!isset($families[$pid])) {
                    $families[$pid] = array('family' => $pid, 'pid' => $pid, 'count' => 0, 'paths' => array());
                }
                $families[$pid]['count']++;
                $families[$pid]['paths'][] = array('path' => $path, 'method' => $method);
            }
        }
        ksort($families, SORT_STRING);

        return array('families' => array_values($families), 'index' => $index);
    }

    /**
     * Enrichers: content-needle synthesizers keyed by template_needle — NOT path claimers, so they
     * are listed apart from the route/claim space.
     *
     * @param array<int,array<string,mixed>> $rules
     * @return array<int,array<string,mixed>>
     */
    private function enrichers(array $rules): array
    {
        $out = array();
        foreach ($rules as $rule) {
            if (!is_array($rule) || !isset($rule['id'])) {
                continue;
            }
            $out[] = array(
                'id' => (string) $rule['id'],
                'needle' => $this->stringList($rule['match']['template_needle'] ?? array()),
            );
        }

        return $out;
    }

    // --- link scanning ----------------------------------------------------------------------

    /**
     * Outbound links for an attack rule: its served body(ies) and any Location header, across the
     * top-level response plus every branch case / traversal allow / arith-eval / iterate node
     * (the same served-shape descent the fingerprint gate uses). Decoy-session rules also get one
     * stub skin render so an authed panel's links are covered.
     *
     * @param array<string,mixed> $rule
     * @return array<int,array<string,mixed>>
     */
    private function attackLinks(array $rule): array
    {
        $links = array();
        foreach ($this->collectServedShapes($rule) as $shape) {
            $this->appendLinks($links, $this->scanBody((string) ($shape['body'] ?? '')));
            $this->appendLinks($links, $this->scanHeaders((array) ($shape['headers'] ?? array())));
        }
        if ((string) ($rule['behavior'] ?? '') === 'decoy-session') {
            $this->appendLinks($links, $this->skinLinks($rule));
        }

        return $this->dedupeLinks($links);
    }

    /**
     * Outbound links for a param entry: its response body/headers plus every traversal allow
     * `content` (a disclosed file body can itself carry links).
     *
     * @param array<string,mixed> $entry
     * @return array<int,array<string,mixed>>
     */
    private function paramLinks(array $entry): array
    {
        $links = array();
        $shapes = array((array) ($entry['response'] ?? array()));
        if (isset($entry['traversal-read']) && is_array($entry['traversal-read'])) {
            foreach ((array) ($entry['traversal-read']['allow'] ?? array()) as $allow) {
                if (is_array($allow) && isset($allow['content']) && is_array($allow['content'])) {
                    $shapes[] = $allow['content'];
                }
            }
            if (isset($entry['traversal-read']['default']['content']) && is_array($entry['traversal-read']['default']['content'])) {
                $shapes[] = $entry['traversal-read']['default']['content'];
            }
        }
        foreach ($shapes as $shape) {
            $this->appendLinks($links, $this->scanBody((string) ($shape['body'] ?? '')));
            $this->appendLinks($links, $this->scanHeaders((array) ($shape['headers'] ?? array())));
        }

        return $this->dedupeLinks($links);
    }

    /**
     * Every served body+headers shape a rule can emit: the top-level response, and the nested
     * branch/traversal/arith-eval/iterate responses.
     *
     * @param array<string,mixed> $rule
     * @return array<int,array<string,mixed>>
     */
    private function collectServedShapes(array $rule): array
    {
        $shapes = array();
        if (isset($rule['response']) && is_array($rule['response'])) {
            $shapes[] = $rule['response'];
        }
        if (isset($rule['branch']['cases']) && is_array($rule['branch']['cases'])) {
            foreach ($rule['branch']['cases'] as $case) {
                if (is_array($case) && isset($case['response']) && is_array($case['response'])) {
                    $shapes[] = $case['response'];
                }
            }
        }
        if (isset($rule['branch']['default']['response']) && is_array($rule['branch']['default']['response'])) {
            $shapes[] = $rule['branch']['default']['response'];
        }
        if (isset($rule['traversal-read']['allow']) && is_array($rule['traversal-read']['allow'])) {
            foreach ($rule['traversal-read']['allow'] as $allow) {
                if (is_array($allow) && isset($allow['content']) && is_array($allow['content'])) {
                    $shapes[] = $allow['content'];
                }
            }
        }
        if (isset($rule['traversal-read']['default']['content']) && is_array($rule['traversal-read']['default']['content'])) {
            $shapes[] = $rule['traversal-read']['default']['content'];
        }
        if (isset($rule['arith-eval']['response']) && is_array($rule['arith-eval']['response'])) {
            $shapes[] = $rule['arith-eval']['response'];
        }
        if (isset($rule['ssti-render']['response']) && is_array($rule['ssti-render']['response'])) {
            $shapes[] = $rule['ssti-render']['response'];
        }
        if (isset($rule['iterate']) && is_array($rule['iterate'])) {
            foreach (array('item', 'response') as $k) {
                if (isset($rule['iterate'][$k]) && is_array($rule['iterate'][$k])) {
                    $shapes[] = $rule['iterate'][$k];
                }
            }
        }

        return $shapes;
    }

    /**
     * One stub skin render of a decoy-session (gate-mode) rule, so the authed panel's links join
     * the manifest. Best-effort: any fault (fail-closed guard, missing owned path) yields no links
     * rather than failing the build.
     *
     * @param array<string,mixed> $rule
     * @return array<int,array<string,mixed>>
     */
    private function skinLinks(array $rule): array
    {
        $config = is_array($rule['decoy-session'] ?? null) ? $rule['decoy-session'] : array();
        if ((string) ($config['mode'] ?? '') !== 'gate') {
            return array();
        }
        $owned = $this->stringList($rule['owns_path'] ?? array());
        if ($owned === array()) {
            return array();
        }
        // Prefer an explicit …/index.php path so the skin renders as the authed dashboard.
        $path = $owned[0];
        foreach ($owned as $p) {
            if (substr($p, -10) === '/index.php') {
                $path = $p;
                break;
            }
        }
        try {
            $emulator = new TemplateAttackEmulator(array($rule), array(), null, null, array(), self::STUB_SEED, self::STUB_KEY);
            // Mint through DecoySession at the SAME stub seed the emulator gates with, so the gate
            // authenticates and skinLinks scans the AUTHED dashboard; a seed mismatch would silently
            // decline to the login page and derive the manifest from the wrong body.
            $cookie = (new DecoySession(self::STUB_KEY, self::STUB_SEED))->mintCookie(
                (string) ($config['cookie_name'] ?? 'session'),
                (string) ($config['cookie_path'] ?? '/')
            );
            $semi = strpos($cookie, ';');
            $cookiePair = $semi === false ? $cookie : substr($cookie, 0, $semi);
            $resp = $emulator->emulate(new RequestContext('GET', $path, '', array('Cookie' => $cookiePair)));
        } catch (Throwable $e) {
            return array();
        }
        if ($resp === null) {
            return array();
        }

        $links = array();
        $this->appendLinks($links, $this->scanBody($resp->body));
        $this->appendLinks($links, $this->scanHeaders($resp->headers));

        return $links;
    }

    /**
     * Scan a body for outbound targets: form actions, hrefs, fetch() calls, and JS url/location
     * assignments. Directive spans ({{…}}) are inert for routing and stripped first.
     *
     * @return array<int,array<string,mixed>>
     */
    private function scanBody(string $body): array
    {
        if ($body === '') {
            return array();
        }
        $patterns = array(
            'form-action' => '/\baction\s*=\s*["\']([^"\']*)["\']/i',
            'href' => '/\bhref\s*=\s*["\']([^"\']*)["\']/i',
            'fetch' => '/\bfetch\s*\(\s*["\']([^"\']*)["\']/i',
            'js-url' => '/\b(?:window\.location(?:\.href)?|url)\s*[:=]\s*["\']([^"\']*)["\']/i',
        );
        $out = array();
        foreach ($patterns as $source => $pattern) {
            if (preg_match_all($pattern, $body, $m) && isset($m[1])) {
                foreach ($m[1] as $target) {
                    $link = $this->classifyTarget((string) $target, $source);
                    if ($link !== null) {
                        $out[] = $link;
                    }
                }
            }
        }

        return $out;
    }

    /**
     * A Location header is a served self-link too (a redirect target).
     *
     * @param array<string,string> $headers
     * @return array<int,array<string,mixed>>
     */
    private function scanHeaders(array $headers): array
    {
        $out = array();
        foreach ($headers as $name => $value) {
            if (strcasecmp((string) $name, 'Location') !== 0) {
                continue;
            }
            $link = $this->classifyTarget((string) $value, 'location');
            if ($link !== null) {
                $out[] = $link;
            }
        }

        return $out;
    }

    /**
     * Reduce a raw link target to a {path, source, relative} record, or null when it is not a
     * routable self-link (an anchor, a scheme URL, an empty/directive-only span). `relative` is
     * true for anything not single-leading-slash root-absolute — the phpMyAdmin failure mode.
     *
     * @return array<string,mixed>|null
     */
    private function classifyTarget(string $target, string $source): ?array
    {
        // Directive placeholders are inert for routing; drop them before deciding.
        $target = preg_replace('/\{\{[^}]*\}\}/', '', $target);
        $target = trim((string) $target);
        if ($target === '' || $target[0] === '#') {
            return null;
        }
        // Strip query + fragment down to the path.
        $q = strpos($target, '?');
        if ($q !== false) {
            $target = substr($target, 0, $q);
        }
        $h = strpos($target, '#');
        if ($h !== false) {
            $target = substr($target, 0, $h);
        }
        if ($target === '') {
            return null;
        }
        // Absolute URLs and non-http pseudo-schemes are not same-site self-links.
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $target) === 1) {
            return null;
        }
        $rootAbsolute = $target[0] === '/' && (strlen($target) < 2 || $target[1] !== '/');

        return array('path' => $target, 'source' => $source, 'relative' => !$rootAbsolute);
    }

    // --- derivation helpers -----------------------------------------------------------------

    /**
     * The method set a rule claims, from its `in:method` match condition. No such condition means
     * the rule matches every method, recorded as the wildcard `*`.
     *
     * @param array<int,array<string,mixed>> $match
     * @return array<int,string>
     */
    private function methodSet(array $match): array
    {
        foreach ($match as $cond) {
            if (!is_array($cond) || ($cond['in'] ?? '') !== 'method') {
                continue;
            }
            $methods = array();
            if (preg_match_all('/[A-Z]+/', strtoupper((string) ($cond['regex'] ?? '')), $m)) {
                foreach ($m[0] as $tok) {
                    if (isset(self::$httpMethods[$tok]) && !in_array($tok, $methods, true)) {
                        $methods[] = $tok;
                    }
                }
            }
            if ($methods !== array()) {
                return $methods;
            }
        }

        return array('*');
    }

    /**
     * @param array<int,array<string,mixed>> $match
     */
    private function hasPathCondition(array $match): bool
    {
        foreach ($match as $cond) {
            if (is_array($cond) && ($cond['in'] ?? '') === 'path' && (string) ($cond['regex'] ?? '') !== '') {
                return true;
            }
        }

        return false;
    }

    /**
     * The literal path an `in:path` condition anchors, when its regex reduces to a fixed string
     * (e.g. `^/api/tags/?$` -> `/api/tags`); null for an alternation/metachar pattern.
     *
     * @param array<int,array<string,mixed>> $match
     */
    private function literalPathAnchor(array $match): ?string
    {
        foreach ($match as $cond) {
            if (!is_array($cond) || ($cond['in'] ?? '') !== 'path') {
                continue;
            }
            $lit = $this->reduceRegexPath((string) ($cond['regex'] ?? ''));
            if ($lit !== null) {
                return $lit;
            }
        }

        return null;
    }

    /**
     * Reduce an `in:path` regex to the single fixed path it anchors, or null when the pattern is an
     * alternation / character class / wildcard no one path represents. Handles both anchor shapes
     * the attack compiler emits: a root-anchored `^/x/?$`, and a segment-anchored
     * `(?:^|/)x(?:/|$)` (matches at any path boundary — its canonical claim is `/x`). Recording the
     * segment-anchored literal lets the route-integrity dangling-link resolver surface a same-path
     * candidate: a decoy whose login form posts to `/session_login.cgi` owns that path via such a
     * regex, not owns_path, so the resolver reports a conditional match-regex candidate rather than
     * "nothing" (the request-dependent match is not proven from the manifest alone).
     */
    private function reduceRegexPath(string $rx): ?string
    {
        if ($rx === '') {
            return null;
        }
        // Leading anchor: '^' (root) or '(?:^|/)' (any segment start) both mean "path begins here".
        if (strncmp($rx, '(?:^|/)', 7) === 0) {
            $rx = '/' . substr($rx, 7);
        } elseif ($rx[0] === '^') {
            $rx = substr($rx, 1);
        }
        // Trailing anchor, in the compiler's forms: (?:/|$), an optional trailing slash then end,
        // or a bare end.
        $rx = preg_replace('/\(\?:\/\|\$\)$/', '', $rx);
        $rx = preg_replace('#/[?*+]\$$#', '', (string) $rx);
        $rx = preg_replace('/\/?\$$/', '', (string) $rx);
        $rx = str_replace(array('\\.', '\\-', '\\/'), array('.', '-', '/'), (string) $rx);
        if ($rx === '' || $rx[0] !== '/') {
            $rx = '/' . $rx;
        }
        // Only a pure literal path qualifies — any leftover metacharacter means it is not fixed.
        if (preg_match('#^/[\w.~@/-]+$#', $rx) === 1) {
            return $rx;
        }

        return null;
    }

    /**
     * The literal anchored prefix of a compiled param regex — the routable path the bucket owns,
     * e.g. `^/@fs/(?P<path>.+)$` -> `/@fs/`. Reads up to the first regex metacharacter.
     */
    private function literalRegexPrefix(string $regex): string
    {
        $rx = preg_replace('/^\^/', '', $regex);
        $rx = str_replace(array('\\.', '\\-', '\\/'), array('.', '-', '/'), (string) $rx);
        if (preg_match('#^(/[A-Za-z0-9._/@-]*)#', (string) $rx, $m) === 1) {
            return $m[1];
        }

        return '';
    }

    private function attackTier(string $id): string
    {
        if (strncmp($id, 'attack-crs-', 11) === 0) {
            return 'attack-crs';
        }
        if (strncmp($id, 'attack-ai-', 10) === 0) {
            return 'attack-ai';
        }

        return 'attack';
    }

    /**
     * The product family for a Band A record: the first tag that names a product (not an
     * attack-class / role / provenance marker), else derived from the id/pid.
     *
     * @param array<int,string> $tags
     */
    private function familyFor(array $tags, string $idOrPid): string
    {
        foreach ($tags as $tag) {
            $t = (string) $tag;
            if ($t === '' || isset(self::$genericTags[$t])) {
                continue;
            }
            if (strncmp($t, 'cve', 3) === 0 || strncmp($t, 'crs-', 4) === 0) {
                continue;
            }

            return $t;
        }

        return $this->familyFromId($idOrPid);
    }

    /** Strip a known tier prefix from an id/pid and take its first segment. */
    private function familyFromId(string $id): string
    {
        $prefixes = array('attack-crs-', 'attack-ai-', 'attack-', 'param-', 'route-ai-', 'route-');
        foreach ($prefixes as $p) {
            if (strncmp($id, $p, strlen($p)) === 0) {
                $id = substr($id, strlen($p));
                break;
            }
        }
        $dash = strpos($id, '-');

        return $dash === false ? $id : substr($id, 0, $dash);
    }

    /**
     * @param array<string,mixed> $entry
     * @return array<string,mixed>|null
     */
    private function firstRoutePidBundle(array $entry): ?array
    {
        foreach ((array) ($entry['b'] ?? array()) as $bundle) {
            if (is_array($bundle) && strncmp((string) ($bundle['pid'] ?? ''), 'route-', 6) === 0) {
                return $bundle;
            }
        }

        return null;
    }

    /**
     * The distinct corpus families a route entry carries, in first-seen order. Every non-route-*
     * bundle counts (route-* is Band A new-page); a corpus bundle with no pid maps to the `unknown`
     * family so a degenerate corpus key is still indexed rather than dropped.
     *
     * @param array<string,mixed> $entry
     * @return array<int,string>
     */
    private function corpusPids(array $entry): array
    {
        $pids = array();
        foreach ((array) ($entry['b'] ?? array()) as $bundle) {
            if (!is_array($bundle)) {
                continue;
            }
            $pid = (string) ($bundle['pid'] ?? '');
            if (strncmp($pid, 'route-', 6) === 0) {
                continue;
            }
            $family = $pid === '' ? 'unknown' : $pid;
            if (!in_array($family, $pids, true)) {
                $pids[] = $family;
            }
        }

        return $pids;
    }

    /**
     * @return array{0:string,1:string} [method, path]
     */
    private function splitRouteKey(string $key): array
    {
        $sp = strpos($key, ' ');
        if ($sp === false) {
            return array('*', $key);
        }

        return array(substr($key, 0, $sp), substr($key, $sp + 1));
    }

    /**
     * @param mixed $value
     * @return array<int,string>
     */
    private function stringList($value): array
    {
        $out = array();
        foreach ((array) $value as $v) {
            if (is_scalar($v)) {
                $out[] = (string) $v;
            }
        }

        return $out;
    }

    /**
     * @param array<int,array<string,mixed>> $routes
     * @return array<int,array<string,mixed>>
     */
    private function dedupeRoutes(array $routes): array
    {
        $seen = array();
        $out = array();
        foreach ($routes as $r) {
            $k = $r['method'] . "\0" . $r['path'] . "\0" . $r['via'];
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $out[] = $r;
        }

        return $out;
    }

    /**
     * @param array<int,array<string,mixed>> $links
     * @param array<int,array<string,mixed>> $add
     */
    private function appendLinks(array &$links, array $add): void
    {
        foreach ($add as $link) {
            $links[] = $link;
        }
    }

    /**
     * @param array<int,array<string,mixed>> $links
     * @return array<int,array<string,mixed>>
     */
    private function dedupeLinks(array $links): array
    {
        $seen = array();
        $out = array();
        foreach ($links as $link) {
            $k = $link['path'] . "\0" . $link['source'] . "\0" . ($link['relative'] ? '1' : '0');
            if (isset($seen[$k])) {
                continue;
            }
            $seen[$k] = true;
            $out[] = $link;
        }

        return $out;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function loadArray(string $path): array
    {
        if ($path === '' || !is_file($path)) {
            return array();
        }
        $data = require $path;

        return is_array($data) ? $data : array();
    }
}
