<?php

declare(strict_types=1);

namespace Funnypot\Core\Manifest;

use Funnypot\Core\Support\PathNormalizer;

/**
 * Route-integrity checks over the derived decoy registry (build/CI-time only — never served).
 * Three checks, each method-aware, catch the phpMyAdmin fall-through class of bug:
 *
 *   (a) collision      Two same-tier claimants own the same path for an overlapping method AND
 *                      different families — order alone decides which product's fake wins.
 *   (b) shadow         An owns_path rule silently masks a DIFFERENT-family static route with no
 *                      declared override intent (an intent tag or a same-family override is fine).
 *   (c) dangling link  A decoy's own emitted self-link (form action, href, redirect) that does not
 *                      resolve back into its own family — a relative link fails outright; a link
 *                      into the generic corpus or to nothing is a warning; a link to a different
 *                      authored family is a failure.
 *
 * Findings carry a severity: FAIL gates CI, WARN is reported but does not gate, INFO records a
 * designed override for visibility. The escape-hatch config (resources/route-integrity.php) can
 * disable a decoy, override an effective priority, or accept a specific finding with a reason.
 *
 * 7.3-clean (no enums/match/arrow-fns); mirrors the runtime resolution precedence
 * (Honeypot::classify / resolveEntry / ownsPath) against manifest data.
 */
final class RouteIntegrity
{
    const FAIL = 'fail';
    const WARN = 'warn';
    const INFO = 'info';
    const ACCEPTED = 'accepted';

    const CHECK_COLLISION = 'collision';
    const CHECK_SHADOW = 'shadow';
    const CHECK_DANGLING = 'dangling';

    /**
     * Tags that mark a rule as a deliberate override of a static route — the operator-confirmed
     * intent set for the shadow check. A shadow carrying one of these is a declared override, not
     * a silent mask.
     *
     * @var array<int,string>
     */
    private static $intentTags = array('mock-auth', 'login', 'panel', 'ai-recon', 'exposure');

    /** Link sources that navigate as a GET; a form action may POST, so it resolves method-agnostically. */
    private static $getNavSources = array('href' => true, 'location' => true, 'js-url' => true, 'fetch' => true);

    /** @var array<string,array<string,mixed>> id => Band A record (disabled ids removed) */
    private $byId = array();

    /** @var array<string,array<int,array<string,string>>> ownershipKey => list of {id,family,method,tier} */
    private $ownsPathOwners = array();

    /** @var array<string,array<string,string>> "METHOD /path" => {id,family} for new-page exact keys */
    private $newPageExact = array();

    /** @var array<string,array<string,string>> "METHOD /path" => {family,pid,tier} corpus index */
    private $corpusIndex = array();

    /** @var array<int,array<string,string>> list of {prefix,id,family,method} param claims */
    private $paramPrefixes = array();

    /** @var array<string,int> id => effective priority (override wins over the record priority) */
    private $effectivePriority = array();

    /**
     * Run all three checks against a manifest under an escape-hatch config.
     *
     * @param array<string,mixed> $manifest  ManifestBuilder::build() output
     * @param array<string,mixed> $config     resources/route-integrity.php (disabled/priority_overrides/accepted)
     * @return array<string,mixed> {findings: list<finding>, disabled_missing: list<string>}
     */
    public function analyze(array $manifest, array $config): array
    {
        $disabled = array();
        foreach ($this->stringList($config['disabled'] ?? array()) as $id) {
            $disabled[$id] = true;
        }
        $overrides = is_array($config['priority_overrides'] ?? null) ? $config['priority_overrides'] : array();
        $accepted = is_array($config['accepted'] ?? null) ? array_values($config['accepted']) : array();

        $this->indexManifest($manifest, $disabled, $overrides);

        $findings = array();
        foreach ($this->collisionFindings() as $f) {
            $findings[] = $f;
        }
        foreach ($this->shadowFindings() as $f) {
            $findings[] = $f;
        }
        foreach ($this->danglingFindings() as $f) {
            $findings[] = $f;
        }

        $findings = $this->applyAccepted($findings, $accepted);

        $disabledMissing = array();
        foreach ($disabled as $id => $_) {
            if (!isset($this->rawIds[$id])) {
                $disabledMissing[] = $id;
            }
        }

        return array('findings' => $findings, 'disabled_missing' => $disabledMissing);
    }

    /** @var array<string,bool> every Band A id seen (before the disabled filter) */
    private $rawIds = array();

    /**
     * @param array<string,mixed> $manifest
     * @param array<string,bool> $disabled
     * @param array<string,mixed> $overrides
     */
    private function indexManifest(array $manifest, array $disabled, array $overrides): void
    {
        $this->byId = array();
        $this->ownsPathOwners = array();
        $this->newPageExact = array();
        $this->paramPrefixes = array();
        $this->effectivePriority = array();
        $this->rawIds = array();

        foreach ((array) ($manifest['bandA'] ?? array()) as $rec) {
            if (!is_array($rec) || !isset($rec['id'])) {
                continue;
            }
            $id = (string) $rec['id'];
            $this->rawIds[$id] = true;
            if (isset($disabled[$id])) {
                continue;
            }
            $this->byId[$id] = $rec;
            $family = (string) ($rec['family'] ?? '');
            $tier = (string) ($rec['tier'] ?? '');
            $prio = isset($overrides[$id]) ? (int) $overrides[$id]
                : (isset($rec['priority']) ? (int) $rec['priority'] : null);
            if ($prio !== null) {
                $this->effectivePriority[$id] = $prio;
            }

            foreach ((array) ($rec['owned_routes'] ?? array()) as $o) {
                if (!is_array($o)) {
                    continue;
                }
                $via = (string) ($o['via'] ?? '');
                $method = strtoupper((string) ($o['method'] ?? '*'));
                $path = (string) ($o['path'] ?? '');
                if ($path === '') {
                    continue;
                }
                if ($via === 'owns_path' || $via === 'match-regex') {
                    $this->ownsPathOwners[PathNormalizer::ownershipKey($path)][] = array(
                        'id' => $id, 'family' => $family, 'method' => $method, 'tier' => $tier, 'via' => $via,
                    );
                } elseif ($via === 'route-key') {
                    $this->newPageExact[$method . ' ' . PathNormalizer::normalize($path)] = array(
                        'id' => $id, 'family' => $family,
                    );
                } elseif ($via === 'param-bucket') {
                    $this->paramPrefixes[] = array(
                        'prefix' => $path, 'id' => $id, 'family' => $family, 'method' => $method,
                    );
                }
            }
        }

        $this->corpusIndex = array();
        foreach ((array) ($manifest['corpus']['index'] ?? array()) as $key => $meta) {
            if (is_array($meta)) {
                $this->corpusIndex[(string) $key] = array(
                    'family' => (string) ($meta['family'] ?? 'unknown'),
                    'pid' => (string) ($meta['pid'] ?? ''),
                    'tier' => (string) ($meta['tier'] ?? 'exact-route'),
                );
            }
        }
    }

    // --- check (a): true collision ----------------------------------------------------------

    /**
     * FAIL a same-tier pair that claims the same ownership key for an overlapping method AND a
     * different family — order alone would decide which product's fake serves. Method-disjoint
     * co-ownership (the phpMyAdmin GET/HEAD gate + POST login) and same-family first-match ordering
     * (the several wordpress xmlrpc rules on /xmlrpc.php) are legitimate and never flagged. New-page
     * decoys key the exact byte-store, so their case/slash variants are distinct keys, not collisions.
     *
     * @return array<int,array<string,mixed>>
     */
    private function collisionFindings(): array
    {
        // attack (attack/attack-crs/attack-ai share one first-match set) + param claims, grouped by
        // ownership key. new-page is exact-keyed, so it cannot host an intra-tier collision.
        $groups = array();
        foreach ($this->ownsPathOwners as $ok => $claims) {
            foreach ($claims as $c) {
                $groups['attack'][$ok][] = $c;
            }
        }
        foreach ($this->paramPrefixes as $p) {
            $groups['param'][PathNormalizer::ownershipKey($p['prefix'])][] = array(
                'id' => $p['id'], 'family' => $p['family'], 'method' => $p['method'], 'tier' => 'param',
            );
        }

        $out = array();
        foreach ($groups as $tier => $keys) {
            foreach ($keys as $ok => $claims) {
                $n = count($claims);
                for ($i = 0; $i < $n; $i++) {
                    for ($j = $i + 1; $j < $n; $j++) {
                        $a = $claims[$i];
                        $b = $claims[$j];
                        if ($a['id'] === $b['id'] || $a['family'] === $b['family']) {
                            continue; // same rule, or same-family first-match order — not a leak
                        }
                        if (!$this->methodsOverlap($a['method'], $b['method'])) {
                            continue; // disjoint methods co-own legitimately
                        }
                        if ($this->priorityDisambiguates($a['id'], $b['id'])) {
                            continue; // an effective-priority difference picks a deterministic winner
                        }
                        $out[] = $this->finding(
                            self::CHECK_COLLISION,
                            self::FAIL,
                            $a['id'],
                            $b['id'],
                            $ok,
                            sprintf(
                                'same-tier collision on %s [%s]: %s (%s) vs %s (%s) — different families, overlapping method',
                                $ok,
                                $tier,
                                $a['id'],
                                $a['method'],
                                $b['id'],
                                $b['method']
                            )
                        );
                    }
                }
            }
        }

        return $out;
    }

    // --- check (b): unintended shadow -------------------------------------------------------

    /**
     * An owns_path claim over a path that also has a static exact-store bundle is an override. It is
     * FINE when it overrides a same-family route (serving a better fake of the same product) or when
     * the owning rule declares intent (a tag in the intent set). A cross-family override with no
     * declared intent is a silent mask → FAIL. Same-family/declared overrides are recorded as INFO.
     *
     * @return array<int,array<string,mixed>>
     */
    private function shadowFindings(): array
    {
        $out = array();
        foreach ($this->byId as $id => $rec) {
            $ownerFamily = (string) ($rec['family'] ?? '');
            $tags = $this->stringList($rec['tags'] ?? array());
            $hasIntent = array_intersect(self::$intentTags, $tags) !== array();

            foreach ((array) ($rec['owned_routes'] ?? array()) as $o) {
                if (!is_array($o) || (string) ($o['via'] ?? '') !== 'owns_path') {
                    continue;
                }
                $ok = PathNormalizer::ownershipKey((string) ($o['path'] ?? ''));
                $shadow = $this->staticBundleAt($ok);
                if ($shadow === null) {
                    continue;
                }
                if ($shadow['family'] === $ownerFamily) {
                    $out[] = $this->finding(self::CHECK_SHADOW, self::INFO, $id, $shadow['label'], $ok,
                        sprintf('%s overrides same-family static route %s', $id, $shadow['label']));
                    continue;
                }
                if ($hasIntent) {
                    $out[] = $this->finding(self::CHECK_SHADOW, self::INFO, $id, $shadow['label'], $ok,
                        sprintf('%s overrides %s (declared intent)', $id, $shadow['label']));
                    continue;
                }
                $out[] = $this->finding(self::CHECK_SHADOW, self::FAIL, $id, $shadow['label'], $ok,
                    sprintf('%s silently shadows different-family static route %s (no override intent)', $id, $shadow['label']));
            }
        }

        return $out;
    }

    /**
     * The first static exact-store bundle whose ownership key equals $ok (a new-page authored decoy
     * or a corpus key), or null. The static-route target space the owns_path override sits over.
     *
     * @return array<string,string>|null {label, family}
     */
    private function staticBundleAt(string $ok): ?array
    {
        foreach ($this->newPageExact as $key => $v) {
            if (PathNormalizer::ownershipKey($this->pathOf($key)) === $ok) {
                return array('label' => $v['id'], 'family' => $v['family']);
            }
        }
        foreach ($this->corpusIndex as $key => $v) {
            if (PathNormalizer::ownershipKey($this->pathOf($key)) === $ok) {
                return array('label' => 'corpus:' . $v['family'], 'family' => $v['family']);
            }
        }

        return null;
    }

    // --- check (c): dangling self-link ------------------------------------------------------

    /**
     * For every Band A decoy self-link: a relative link fails outright (a browser and a scanner
     * resolve it against different bases — the phpMyAdmin failure mode). Otherwise resolve the target
     * through the real precedence and compare the winner's family to the decoy's own.
     *
     * @return array<int,array<string,mixed>>
     */
    private function danglingFindings(): array
    {
        $out = array();
        foreach ($this->byId as $id => $rec) {
            $family = (string) ($rec['family'] ?? '');
            foreach ((array) ($rec['outbound_links'] ?? array()) as $link) {
                if (!is_array($link)) {
                    continue;
                }
                $path = (string) ($link['path'] ?? '');
                $source = (string) ($link['source'] ?? '');
                if ($path === '') {
                    continue;
                }
                if (!empty($link['relative'])) {
                    $out[] = $this->finding(self::CHECK_DANGLING, self::FAIL, $id, '', $path,
                        sprintf('%s emits a RELATIVE self-link %s (%s) — resolve base-dependent; use a root-absolute path', $id, $path, $source));
                    continue;
                }
                $r = $this->resolveLink($path, $source);
                if (in_array($family, $r['families'], true)) {
                    continue; // resolves back in-family
                }
                $winnerFamily = $r['families'] === array() ? '(none)' : $r['families'][0];
                if ($r['band'] === 'authored') {
                    $out[] = $this->finding(self::CHECK_DANGLING, self::FAIL, $id, $r['winner'], $path,
                        sprintf('%s links to %s → resolves to different authored family %s (%s)', $id, $path, $winnerFamily, $r['winner']));
                } elseif ($r['band'] === 'unanchored') {
                    $out[] = $this->finding(self::CHECK_DANGLING, self::FAIL, $id, $r['winner'], $path,
                        sprintf('%s links to %s → swallowed by an unanchored class detector', $id, $path));
                } elseif ($r['band'] === 'corpus') {
                    $out[] = $this->finding(self::CHECK_DANGLING, self::WARN, $id, $r['winner'], $path,
                        sprintf('%s links to %s → resolves into the generic corpus family %s', $id, $path, $winnerFamily));
                } else { // nothing
                    $out[] = $this->finding(self::CHECK_DANGLING, self::WARN, $id, '', $path,
                        sprintf('%s links to %s → resolves to nothing (404/LLM)', $id, $path));
                }
            }
        }

        return $out;
    }

    /**
     * Resolve a self-link target the way the engine would (owns_path override → exact store → param),
     * returning the band it lands in and the candidate winner families. A form action may POST, so it
     * resolves method-agnostically; every other link source navigates as a GET.
     *
     * @return array<string,mixed> {band: authored|corpus|param|unanchored|nothing, families: list<string>, winner: string}
     */
    private function resolveLink(string $path, string $source): array
    {
        $methodAgnostic = !isset(self::$getNavSources[$source]);
        $navMethods = $methodAgnostic ? array('POST', 'GET', 'HEAD') : array('GET', 'HEAD');
        $norm = PathNormalizer::normalize($path);
        $ok = PathNormalizer::ownershipKey($path);

        // owns_path / match-regex override — wins over the static store when a method-compatible rule
        // owns the key (the runtime path-override behaviour).
        if (isset($this->ownsPathOwners[$ok])) {
            $families = array();
            $winner = '';
            foreach ($this->ownsPathOwners[$ok] as $c) {
                if ($methodAgnostic || $c['method'] === '*' || in_array($c['method'], $navMethods, true)) {
                    if (!in_array($c['family'], $families, true)) {
                        $families[] = $c['family'];
                    }
                    if ($winner === '') {
                        $winner = $c['id'];
                    }
                }
            }
            if ($families !== array()) {
                return array('band' => 'authored', 'families' => $families, 'winner' => $winner);
            }
        }

        // exact store: new-page authored keys, then corpus keys, over the resolveEntry variants.
        foreach ($this->keyVariants($norm, $navMethods) as $key) {
            if (isset($this->newPageExact[$key])) {
                return array('band' => 'authored', 'families' => array($this->newPageExact[$key]['family']), 'winner' => $this->newPageExact[$key]['id']);
            }
            if (isset($this->corpusIndex[$key])) {
                return array('band' => 'corpus', 'families' => array($this->corpusIndex[$key]['family']), 'winner' => $key);
            }
        }

        // param prefix bucket.
        foreach ($this->paramPrefixes as $p) {
            if ($p['prefix'] !== '' && strncmp($norm, $p['prefix'], strlen($p['prefix'])) === 0) {
                return array('band' => 'authored', 'families' => array($p['family']), 'winner' => $p['id']);
            }
        }

        // Nothing owns it. An unanchored payload detector only fires on an attack payload, never on a
        // benign self-link navigation, so a plain link that reaches here dead-ends at the 404/LLM.
        return array('band' => 'nothing', 'families' => array(), 'winner' => '(404)');
    }

    /**
     * The exact-store lookup keys resolveEntry would try for a GET-style navigation: the path and its
     * trailing-slash and lowercase variants, across the navigation methods.
     *
     * @param array<int,string> $methods
     * @return array<int,string>
     */
    private function keyVariants(string $norm, array $methods): array
    {
        $paths = array($norm);
        if ($norm !== '/') {
            $paths[] = substr($norm, -1) === '/' ? rtrim($norm, '/') : $norm . '/';
        }
        $lower = strtolower($norm);
        if ($lower !== $norm) {
            $paths[] = $lower;
        }
        $keys = array();
        foreach ($methods as $m) {
            foreach ($paths as $p) {
                $keys[] = $m . ' ' . $p;
            }
        }

        return $keys;
    }

    // --- escape hatches ---------------------------------------------------------------------

    /**
     * Downgrade any FAIL/WARN finding an `accepted` entry matches to ACCEPTED, attaching its reason.
     * An entry matches on path plus its id(s): {a[,b],path}. A missing b matches a one-sided finding.
     *
     * @param array<int,array<string,mixed>> $findings
     * @param array<int,array<string,mixed>> $accepted
     * @return array<int,array<string,mixed>>
     */
    private function applyAccepted(array $findings, array $accepted): array
    {
        foreach ($findings as &$f) {
            if ($f['severity'] !== self::FAIL && $f['severity'] !== self::WARN) {
                continue;
            }
            foreach ($accepted as $entry) {
                if (!is_array($entry) || !$this->acceptMatches($entry, $f)) {
                    continue;
                }
                $f['severity'] = self::ACCEPTED;
                $f['accepted_reason'] = (string) ($entry['reason'] ?? '');
                break;
            }
        }
        unset($f);

        return $findings;
    }

    /**
     * @param array<string,mixed> $entry
     * @param array<string,mixed> $finding
     */
    private function acceptMatches(array $entry, array $finding): bool
    {
        if (isset($entry['check']) && (string) $entry['check'] !== $finding['check']) {
            return false;
        }
        if ((string) ($entry['path'] ?? '') !== (string) $finding['path']) {
            return false;
        }
        $ids = array($finding['a'], $finding['b']);
        $a = (string) ($entry['a'] ?? '');
        if ($a === '' || !in_array($a, $ids, true)) {
            return false;
        }
        $b = (string) ($entry['b'] ?? '');
        if ($b !== '' && !in_array($b, $ids, true)) {
            return false;
        }

        return true;
    }

    // --- small helpers ----------------------------------------------------------------------

    /** Two method tokens overlap when either is the wildcard `*` or they are equal. */
    private function methodsOverlap(string $a, string $b): bool
    {
        return $a === '*' || $b === '*' || $a === $b;
    }

    private function priorityDisambiguates(string $a, string $b): bool
    {
        if (!isset($this->effectivePriority[$a]) || !isset($this->effectivePriority[$b])) {
            return false;
        }

        return $this->effectivePriority[$a] !== $this->effectivePriority[$b];
    }

    private function pathOf(string $routeKey): string
    {
        $sp = strpos($routeKey, ' ');

        return $sp === false ? $routeKey : substr($routeKey, $sp + 1);
    }

    /**
     * @return array<string,mixed>
     */
    private function finding(string $check, string $severity, string $a, string $b, string $path, string $message): array
    {
        return array(
            'check' => $check,
            'severity' => $severity,
            'a' => $a,
            'b' => $b,
            'path' => $path,
            'message' => $message,
        );
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
}
