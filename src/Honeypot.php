<?php

declare(strict_types=1);

namespace Funnypot;

use Funnypot\Contracts\CompiledStore;
use Funnypot\Response\EmulatorRegistry;
use Funnypot\Store\PhpArrayStore;
use Funnypot\Support\PathNormalizer;
use Funnypot\Support\PersonaSelector;
use Funnypot\Support\Severity;
use Funnypot\Synthesis\ResponseSynthesizer;
use Funnypot\Template\TemplateAttackEmulator;

/**
 * Core engine. Framework-agnostic and side-effect-free (all logging/scoring/banning
 * happen in the host app's Observer).
 *
 * detect() is always safe to call — it routes an incoming request to the template(s)
 * it probes for and returns a signal. respond() honours Config: it only serves a fake
 * when the app has opted into respond mode and every safety gate passes.
 */
final class Honeypot implements Engine
{
    private Config $config;
    private Observer $observer;
    private ResponseSynthesizer $synthesizer;
    private ?TemplateAttackEmulator $attackEmulator;

    /** @var string[] template ids/pids/tags never served: Config->exclude merged with the disabled catalog set */
    private array $effectiveExclude;
    private bool $nucleiEnabled;

    public function __construct(
        private CompiledStore $store,
        ?Config $config = null,
        ?Observer $observer = null
    ) {
        $this->config = $config ?? new Config();
        $this->observer = $observer ?? new NullObserver();
        $this->synthesizer = new ResponseSynthesizer(
            EmulatorRegistry::default(),
            $this->config->responseStyle,
            $this->config->serverHeader,
            $this->config->poweredBy
        );

        // What we will not serve is driven by primitives on Config: the exclude deny-set (template
        // ids / pids / tags) and the nuclei-corpus group flag. An operator UI (the app's emulation
        // catalog) resolves its toggles into these before constructing the engine; the engine stays
        // free of any catalog dependency. A disabled attack id in the exclude set is also skipped.
        $this->effectiveExclude = $this->config->exclude;
        $this->nucleiEnabled = $this->config->nucleiReflection;

        $this->attackEmulator = $this->config->attackEmulation
            ? TemplateAttackEmulator::fromPackage()->disable($this->config->exclude)
            : null;
    }

    /**
     * Build against the artifact bundled with the package. Pass a Config to enable
     * respond mode; the default is inert (detect only).
     */
    public static function default(?Config $config = null, ?Observer $observer = null): self
    {
        return new self(PhpArrayStore::fromPackage(), $config, $observer);
    }

    /**
     * Back-compat detection shim: detect() is classify() against an empty SiteProfile, projected
     * to its Detection. No caller breaks (two-phase design §2.1).
     */
    public function detect(RequestContext $r): Detection
    {
        return $this->classify($r, SiteProfile::empty())->detection;
    }

    /**
     * Content detection only (two-phase design §2.1): route resolution, then — on a miss — the
     * attack-payload matcher, consulting the SiteProfile real-route oracle. Always safe to call:
     * no gates, no I/O, no side effects. Answers "what is this request, as content?" — never
     * "should we act?". The request-shape bot signals ride on the Verdict (Phase 1b).
     */
    public function classify(RequestContext $r, SiteProfile $profile): Verdict
    {
        $signals = $this->botSignals($r);
        $anomaly = $signals->weight;

        $resolved = $this->resolveEntry($r->method, $r->path);
        if ($resolved !== null) {
            [$key, $entry] = $resolved;
            $bundles = $entry['b'] ?? [];

            // An entry with no servable bundles, or a path the host declares as a genuine route,
            // is not a probe — never shadow a live endpoint (M2). Mirrors respond()'s early null.
            if ($bundles === [] || $profile->hasRoute($r->method, PathNormalizer::normalize($r->path))) {
                return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
            }

            $detection = $this->detectionFor($key, $this->detectIds($entry));
            $handle = FakeHandle::route($key);

            // A bare root/homepage entry (all bundles sig=1) is an ordinary-visitor path: classify
            // clean natively (the probe-signature predicate is a policy input, not content). Keep
            // the handle so the policy can still synthesize when it supplies one.
            $classification = $this->isRootEntry($bundles) ? Verdict::CLEAN : Verdict::SCANNER_PROBE;

            return new Verdict($classification, $detection, $detection->highestSeverity, $anomaly, $signals, $handle);
        }

        if ($this->attackEmulator !== null) {
            $matched = $this->attackEmulator->matchRule($r);
            if ($matched !== null) {
                $rule = $matched['rule'];
                $detection = TemplateAttackEmulator::detectionForRule($rule);
                $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $matched['captures']);

                return new Verdict(
                    Verdict::ATTACK_CLASS,
                    $detection,
                    $detection->highestSeverity,
                    $anomaly,
                    $signals,
                    $handle
                );
            }
        }

        return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
    }

    /**
     * True when every servable bundle for an entry is a root/homepage class (sig=1).
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function isRootEntry(array $bundles): bool
    {
        foreach ($bundles as $bundle) {
            if ((int) ($bundle['sig'] ?? 0) !== 1) {
                return false;
            }
        }

        return $bundles !== [];
    }

    /**
     * Request-shape bot signals (decision S / design §2.4): header-presence, fetch-metadata /
     * client-hint absence, self-consistency contradictions, and a digit-stripped structural
     * header fingerprint. Cheap, position-blind, no I/O. Each fires a flag and adds a small
     * weight; the composite "is this a bot?" call is the policy's, never core's. No version-age
     * detection — the digit-stripping tolerates old-but-legit clients.
     *
     * INPUT-side only: nothing computed here is ever emitted in a response (invariant #1).
     */
    private function botSignals(RequestContext $r): BotSignalSet
    {
        $h = $this->lowercaseHeaders($r->headers);
        $ua = isset($h['user-agent']) ? trim($h['user-agent']) : '';
        $uaClass = $this->classifyUserAgent($ua);

        $flags = [];
        $weight = 0;

        // Header presence — the coarsest signal.
        if (!isset($h['accept'])) {
            $flags[BotSignalSet::MISSING_ACCEPT] = true;
            $weight += 5;
        }
        if (!isset($h['accept-language'])) {
            $flags[BotSignalSet::MISSING_ACCEPT_LANGUAGE] = true;
            $weight += 5;
        }
        if (!isset($h['accept-encoding'])) {
            $flags[BotSignalSet::MISSING_ACCEPT_ENCODING] = true;
            $weight += 5;
        }
        if ($ua === '') {
            $flags[BotSignalSet::EMPTY_USER_AGENT] = true;
            $weight += 10;
        }
        if ($uaClass === BotSignalSet::UA_SCANNER) {
            $flags[BotSignalSet::SCANNER_USER_AGENT] = true;
            $weight += 20;
        }

        $claimsBrowser = stripos($ua, 'mozilla') !== false;
        $claimsChromium = preg_match('/chrome|chromium|crios|edg\//i', $ua) === 1;
        $hasFetchMeta = isset($h['sec-fetch-site']) || isset($h['sec-fetch-mode'])
            || isset($h['sec-fetch-dest']) || isset($h['sec-fetch-user']);
        $hasClientHints = isset($h['sec-ch-ua']) || isset($h['sec-ch-ua-mobile'])
            || isset($h['sec-ch-ua-platform']);

        // Fetch-metadata / client-hint absence — low weight alone; leans on the pairing below.
        if (!$hasFetchMeta) {
            $flags[BotSignalSet::MISSING_FETCH_METADATA] = true;
            $weight += 2;
        }
        if (!$hasClientHints) {
            $flags[BotSignalSet::MISSING_CLIENT_HINTS] = true;
            $weight += 2;
        }

        // Self-consistency contradictions — a contradiction beats an absence.
        if ($claimsChromium && !$hasClientHints && !$hasFetchMeta) {
            $flags[BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS] = true;
            $weight += 15;
        }
        if ($claimsBrowser && isset($h['accept']) && trim($h['accept']) === '*/*') {
            $flags[BotSignalSet::ACCEPT_WILDCARD_FROM_BROWSER] = true;
            $weight += 10;
        }
        if ($this->isHttp2($r->httpVersion) && isset($h['connection'])) {
            $flags[BotSignalSet::H2_FORBIDDEN_CONNECTION] = true;
            $weight += 15;
        }
        if (isset($h['accept-encoding']) && stripos($h['accept-encoding'], 'gzip') === false) {
            $flags[BotSignalSet::ACCEPT_ENCODING_NO_GZIP] = true;
            $weight += 5;
        }
        if ($this->platformMismatch($ua, $h)) {
            $flags[BotSignalSet::UA_PLATFORM_MISMATCH] = true;
            $weight += 10;
        }

        return new BotSignalSet($flags, $weight, $uaClass, $this->structuralFingerprint($r->headers));
    }

    /**
     * @param array<string,string> $headers
     * @return array<string,string> name lower-cased (case-insensitive access)
     */
    private function lowercaseHeaders(array $headers): array
    {
        $out = [];
        foreach ($headers as $name => $value) {
            $out[strtolower((string) $name)] = (string) $value;
        }

        return $out;
    }

    /** Coarse UA class. Tool names are matched INPUT-side only and never emitted. */
    private function classifyUserAgent(string $ua): string
    {
        if ($ua === '') {
            return BotSignalSet::UA_EMPTY;
        }
        if (preg_match('/nmap|sqlmap|nuclei|nikto|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|feroxbuster|arachni|httpx|zaproxy|semrush/i', $ua) === 1) {
            return BotSignalSet::UA_SCANNER;
        }
        if (preg_match('#curl|wget|python-requests|python-urllib|urllib|go-http-client|libwww|okhttp|axios|node-fetch|guzzle|java/|apache-httpclient|ruby|perl|winhttp#i', $ua) === 1) {
            return BotSignalSet::UA_SCRIPT;
        }
        if (stripos($ua, 'mozilla') !== false) {
            return BotSignalSet::UA_BROWSER;
        }

        return BotSignalSet::UA_UNKNOWN;
    }

    private function isHttp2(string $version): bool
    {
        return strncmp($version, '2', 1) === 0 || strncmp($version, '3', 1) === 0;
    }

    /**
     * UA-declared OS vs the Sec-CH-UA-Platform hint. A mismatch (UA says Windows, hint says Linux)
     * is a sharp forgery signal. Only fires when BOTH are known.
     *
     * @param array<string,string> $h lower-cased headers
     */
    private function platformMismatch(string $ua, array $h): bool
    {
        if (!isset($h['sec-ch-ua-platform'])) {
            return false;
        }
        $hint = strtolower(trim($h['sec-ch-ua-platform'], " \t\"'"));
        $uaOs = $this->userAgentOs($ua);
        if ($hint === '' || $uaOs === '') {
            return false;
        }
        // Normalize the hint to the UA vocabulary.
        if ($hint === 'macos') {
            $hint = 'mac';
        }

        return $hint !== $uaOs;
    }

    private function userAgentOs(string $ua): string
    {
        if (stripos($ua, 'windows') !== false) {
            return 'windows';
        }
        if (stripos($ua, 'android') !== false) {
            return 'android';
        }
        if (stripos($ua, 'iphone') !== false || stripos($ua, 'ipad') !== false) {
            return 'ios';
        }
        if (stripos($ua, 'mac os') !== false || stripos($ua, 'macintosh') !== false) {
            return 'mac';
        }
        if (stripos($ua, 'linux') !== false || stripos($ua, 'x11') !== false) {
            return 'linux';
        }

        return '';
    }

    /** Comma-list headers whose internal token order is not significant. */
    private const LIST_HEADERS = [
        'accept' => true,
        'accept-encoding' => true,
        'accept-language' => true,
        'accept-charset' => true,
        'connection' => true,
        'sec-ch-ua' => true,
        'te' => true,
        'cache-control' => true,
    ];

    /**
     * Digit-stripped, list-sorted structural header fingerprint (the JA4-H idea in PHP): strip
     * version digits from values and sort list-header tokens, so a Chromium version bump or a
     * reordered Accept keep the same fingerprint; header order + count still distinguish client
     * families (browser vs curl/python/Go). A feature on the Verdict, never an emitted value.
     *
     * @param array<string,string> $headers
     */
    private function structuralFingerprint(array $headers): string
    {
        $parts = [];
        foreach ($headers as $name => $value) {
            $lname = strtolower((string) $name);
            $v = preg_replace('/\d+/', '', (string) $value);
            if (isset(self::LIST_HEADERS[$lname])) {
                $tokens = array_map('trim', explode(',', (string) $v));
                sort($tokens);
                $v = implode(',', $tokens);
            }
            $parts[] = $lname . '=' . $v;
        }

        return count($headers) . ':' . implode('&', $parts);
    }

    /**
     * Resolve a request to a route entry with cheap fallbacks, so the GET-only index
     * still answers the POST/HEAD and slash/case variants scanners send (a third of
     * probes are POST). Order: exact match; then the GET bundle for the same path (for
     * POST/HEAD only — never OPTIONS/TRACE, which a real server answers differently);
     * then trailing-slash and lower-cased path variants.
     *
     * @return array{0:string,1:array<string,mixed>}|null [routing key, entry]
     */
    private function resolveEntry(string $method, string $path): ?array
    {
        $upper = strtoupper($method);
        $norm = PathNormalizer::normalize($path);

        $methods = [$upper];
        if (($upper === 'POST' || $upper === 'HEAD') && !in_array('GET', $methods, true)) {
            $methods[] = 'GET';
        }

        $paths = [$norm];
        if ($norm !== '/') {
            $paths[] = substr($norm, -1) === '/' ? rtrim($norm, '/') : $norm . '/';
        }
        $lower = strtolower($norm);
        if ($lower !== $norm) {
            $paths[] = $lower;
        }

        foreach ($methods as $m) {
            foreach ($paths as $p) {
                $key = $m . ' ' . $p;
                $entry = $this->store->lookup($key);
                if ($entry !== null) {
                    return [$key, $entry];
                }
            }
        }

        return null;
    }

    /**
     * Back-compat facade over classify() + synthesize() (two-phase design §6.6). Core is
     * position-blind and action-free; this method layers the LEGACY Config gates + Observer +
     * serve-delay back on so the existing app (and this suite) keep byte-identical behavior until
     * the caller migrates to funnypot-policy. New consumers call classify()/synthesize() directly.
     */
    public function respond(RequestContext $r): ?SynthesizedResponse
    {
        // Ground-truth switches first: a tripped kill switch or a trusted scanner must NEVER see a
        // fake, and respond mode must be explicitly enabled. No observer, no work (as before).
        if ($this->config->killSwitchTripped() || !$this->config->respondEnabled() || $this->config->isTrusted($r)) {
            return null;
        }

        // FALLBACK position: no real app behind the engine, so an empty SiteProfile.
        $verdict = $this->classify($r, SiteProfile::empty());
        $seed = $this->config->seedFor($r);

        if ($verdict->classification === Verdict::ATTACK_CLASS) {
            return $this->respondAttack($r, $verdict, $seed);
        }

        $handle = $verdict->fakeHandle;
        if ($handle === null || $handle->kind !== FakeHandle::KIND_ROUTE) {
            // A genuine miss / real route / empty entry: the app serves its own 404 (no observer).
            return null;
        }

        // A routed probe. Detection covers EVERY routed template (the full 'd' id-list); signal
        // the app before any serve decision.
        $this->observer->onDetection($r, $verdict->detection);

        if (!$this->config->gateOpen($r)) {
            return $this->declined($r, Outcome::GATE_CLOSED);
        }

        // Root / homepage-class entries (classified clean) never fake-vuln an ordinary visitor
        // unless the app's probe-signature predicate says so.
        if ($verdict->classification === Verdict::CLEAN && !$this->config->hasProbeSignature($r)) {
            return $this->declined($r, Outcome::NO_SIGNATURE);
        }

        $built = $this->buildFake($verdict, SiteProfile::empty(), $seed);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        if (!$this->observer->shouldRespond($r, $verdict->detection)) {
            return $this->declined($r, Outcome::VETOED);
        }

        $this->serveDelay();
        $this->observer->onOutcome($r, $built['r'], Outcome::SERVED);

        return $built['r'];
    }

    /**
     * The attack-class branch of the facade. Emulation bypasses the app-suspicion gate (an
     * injection payload is its own signal), exactly as the legacy path did; kill-switch / mode /
     * trusted are already applied above.
     */
    private function respondAttack(RequestContext $r, Verdict $verdict, string $seed): ?SynthesizedResponse
    {
        $this->observer->onDetection($r, $verdict->detection);

        $built = $this->buildFake($verdict, SiteProfile::empty(), $seed);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        $this->serveDelay();
        $this->observer->onOutcome($r, $built['r'], Outcome::SERVED);

        return $built['r'];
    }

    /**
     * Build a fake from a Verdict's fakeHandle (two-phase design §2.2). Invoked only when the
     * caller's policy chose to deceive — core never decides that. Pure function of (verdict,
     * profile, seed) + the compiled store: same inputs => same bytes. null is the sole "no fake"
     * signal (degrade to the caller's 404); a synthesis fault never escapes as a 5xx.
     */
    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed): ?SynthesizedResponse
    {
        return $this->buildFake($verdict, $profile, $seed)['r'];
    }

    private function declined(RequestContext $r, string $reason): ?SynthesizedResponse
    {
        $this->observer->onOutcome($r, null, $reason);

        return null;
    }

    /** Pause (base + random jitter) so replies aren't instant/uniform. No-op when latency is 0. */
    private function serveDelay(): void
    {
        $delay = $this->config->serveDelayMicros();
        if ($delay > 0) {
            usleep($delay);
        }
    }

    /**
     * The synthesis core shared by synthesize() and the respond() facade: turn a fakeHandle into
     * a fake or a decline reason. Content-integrity only (candidates / persona / ceiling / exclude
     * / size cap for a route; render + ceiling + cap for an attack) — no gates, no observer, no
     * delay. The WHEN/whether/side-effect decisions are the caller's (the facade / the policy).
     *
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildFake(Verdict $verdict, SiteProfile $profile, string $seed): array
    {
        $handle = $verdict->fakeHandle;
        if ($handle === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }
        if ($handle->kind === FakeHandle::KIND_ROUTE) {
            return $this->buildRouteFake($handle, $profile, $seed);
        }
        if ($handle->kind === FakeHandle::KIND_ATTACK) {
            return $this->buildAttackFake($handle, $seed);
        }

        // Unknown / llm kinds are host-injected synthesizers; core builds nothing.
        return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
    }

    /**
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildRouteFake(FakeHandle $handle, SiteProfile $profile, string $seed): array
    {
        $key = (string) $handle->key;

        // Never shadow a declared real route (BEFORE position). The key is '<METHOD> <path>'.
        $sp = strpos($key, ' ');
        if ($sp !== false && $profile->hasRoute(substr($key, 0, $sp), substr($key, $sp + 1))) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $entry = $this->store->lookup($key);
        $allBundles = $entry === null ? [] : ($entry['b'] ?? []);

        // Filter to servable candidates BEFORE the persona pick: excluded bundles and bundles
        // above the severity ceiling are removed so a seed never lands on a refused bundle.
        $candidates = $this->candidates($allBundles);
        if ($candidates === []) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $bundle = PersonaSelector::pick($candidates, $seed);
        if ($bundle === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $satisfies = $this->detectionFor($key, $bundle['t'] ?? []);
        $response = $this->synthesizer->synthesize($bundle, $satisfies, $seed);
        if ($response === null) {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }

        // Never emit an oversized body (no tarpit/amplifier unless the app opts in).
        if (strlen($response->body) > $this->config->maxBodyBytes) {
            return ['r' => null, 'reason' => Outcome::OVER_CAP];
        }

        return ['r' => $response, 'reason' => Outcome::SERVED];
    }

    /**
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildAttackFake(FakeHandle $handle, string $seed): array
    {
        if ($this->attackEmulator === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $rule = $this->attackEmulator->ruleById((string) $handle->ruleId);
        if ($rule === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        // Seed fake values from the persona so a given attacker sees stable, but per-attacker
        // distinct, fabricated secrets (not one shared seed-0 value that would fingerprint).
        $response = $this->attackEmulator->renderRule($rule, $handle->captures, crc32($seed));
        if ($response === null) {
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE]; // CRLF header-split guard
        }
        if (Severity::exceeds($response->satisfies->highestSeverity, $this->config->severityCeiling)) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }
        if (strlen($response->body) > $this->config->maxBodyBytes) {
            return ['r' => null, 'reason' => Outcome::OVER_CAP];
        }

        return ['r' => $response, 'reason' => Outcome::SERVED];
    }

    /**
     * Servable bundles: not excluded, and at or below the severity ceiling. No cost
     * for the exclude pass when the deny list is empty.
     *
     * @param array<int,array<string,mixed>> $bundles
     * @return array<int,array<string,mixed>>
     */
    private function candidates(array $bundles): array
    {
        $ceiling = $this->config->severityCeiling;
        $deny = $this->effectiveExclude === [] ? null : array_flip($this->effectiveExclude);

        $kept = [];
        foreach ($bundles as $bundle) {
            // Corpus reflection off: drop nuclei-derived bundles but keep folded product decoys
            // (their pid is route-*), which are a separately-toggled capability.
            if (!$this->nucleiEnabled && strncmp((string) ($bundle['pid'] ?? ''), 'route-', 6) !== 0) {
                continue;
            }
            if (Severity::exceeds((string) ($bundle['sev'] ?? 'unknown'), $ceiling)) {
                continue;
            }
            if ($deny !== null && $this->isExcluded($bundle, $deny)) {
                continue;
            }
            $kept[] = $bundle;
        }

        return $kept;
    }

    /**
     * True when a bundle names an excluded template id, product, or tag. Coarse by
     * design: exclude means "never serve this persona".
     *
     * @param array<string,mixed> $bundle
     * @param array<string,int>   $deny
     */
    private function isExcluded(array $bundle, array $deny): bool
    {
        if (isset($deny[$bundle['pid'] ?? ''])) {
            return true;
        }
        foreach ($bundle['t'] ?? [] as $id) {
            if (isset($deny[$id])) {
                return true;
            }
            $meta = $this->store->template($id);
            foreach ((array) ($meta['tags'] ?? []) as $tag) {
                if (isset($deny[$tag])) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The full detect id-list for an entry: the explicit `'d'` list on a capped key, or
     * the union of the served bundles' template ids everywhere else. Capping the served
     * ('b') set never trims detect — a one-line, backward-compatible read (the Phase-1
     * fixture has no `'d'`, so it falls back to the union).
     *
     * @param array<string,mixed> $entry
     * @return string[]
     */
    private function detectIds(array $entry): array
    {
        if (isset($entry['d'])) {
            return $entry['d'];
        }

        $ids = [];
        foreach ($entry['b'] ?? [] as $bundle) {
            foreach ($bundle['t'] ?? [] as $id) {
                $ids[] = $id;
            }
        }

        return $ids;
    }

    /**
     * Build a Detection covering a flat list of template ids (deduped, in order).
     *
     * @param string[] $ids
     */
    private function detectionFor(string $key, array $ids): Detection
    {
        $matches = [];
        $seen = [];
        $ceiling = '';
        foreach ($ids as $id) {
            if (isset($seen[$id])) {
                continue;
            }
            $seen[$id] = true;

            $meta = $this->store->template($id);
            if ($meta === null) {
                continue;
            }

            $severity = (string) ($meta['sev'] ?? 'unknown');
            $matches[] = new TemplateMatch(
                $id,
                $severity,
                (array) ($meta['tags'] ?? []),
                (string) ($meta['name'] ?? '')
            );
            $ceiling = $ceiling === '' ? $severity : Severity::ceiling($ceiling, $severity);
        }

        if ($matches === []) {
            return Detection::none();
        }

        return new Detection(true, $matches, $key, $ceiling);
    }
}
