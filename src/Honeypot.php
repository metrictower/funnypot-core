<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Contracts\CompiledStore;
use Funnypot\Core\Response\EmulatorRegistry;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PathNormalizer;
use Funnypot\Core\Support\PersonaSelector;
use Funnypot\Core\Support\Severity;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\Template\TemplateAttackEmulator;

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
    /** @var CompiledStore */
    private $store;

    /** @var Config */
    private $config;

    /** @var Observer */
    private $observer;

    /** @var ResponseSynthesizer */
    private $synthesizer;

    /** @var TemplateAttackEmulator|null */
    private $attackEmulator;

    /** @var string[] template ids/pids/tags never served: Config->exclude merged with the disabled catalog set */
    private $effectiveExclude;

    /** @var array<string,int> Config->ignoreTemplates flipped to a set: ids/tags never allowed to drive a detection */
    private $ignoreTemplates;

    /** @var bool */
    private $nucleiEnabled;

    public function __construct(
        CompiledStore $store,
        ?Config $config = null,
        ?Observer $observer = null
    ) {
        $this->store = $store;
        $this->config = $config ?? new Config();
        $this->observer = $observer ?? new NullObserver();

        // One per-deploy identity seed drives {{persona.*}} in both runtime renderers below, so the
        // template tier and the app LLM tier present one coherent site identity. Fabricated {{fake.*}}
        // secrets stay per-request (per-attacker) — only the identity is deploy-stable.
        $personaSeed = $this->config->deploySeed();

        // FP-0239: opt-in prompt-injection seeding. Read the gate + build the per-deploy self-beacon
        // canary off Config, then hand both DISCRETE values down the real render path
        // (EmulatorRegistry::default → RouteTemplateEmulator). No SynthesisConfig — it is dead on this
        // path. The beacon canary is built only when the gate is on AND a beacon URL + a signing key
        // are configured; the URL carries a server-signed token (Honeytoken::beaconToken, same HMAC as
        // the bait cookie — no new crypto), never any attacker input.
        $beaconCanary = [];
        $beaconKey = $this->config->decoySessionKey ?? $this->config->honeytokenKey;
        if (
            $this->config->promptInjectionSeeding
            && $this->config->beaconUrl !== null && $this->config->beaconUrl !== ''
            && $beaconKey !== null && $beaconKey !== ''
        ) {
            $token = (new Honeytoken($beaconKey))->beaconToken((string) $personaSeed);
            $sep = strpos($this->config->beaconUrl, '?') === false ? '?' : '&';
            $beaconCanary['beacon'] = $this->config->beaconUrl . $sep . 't=' . $token;
        }

        $this->synthesizer = new ResponseSynthesizer(
            EmulatorRegistry::default($personaSeed, $this->config->promptInjectionSeeding, $beaconCanary),
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

        // Detection-side deny-set, distinct from $effectiveExclude (serving). Flipped once here so
        // the per-request membership test in applyIgnore() is O(1).
        $this->ignoreTemplates = array_flip($this->config->ignoreTemplates);

        $this->attackEmulator = $this->config->attackEmulation
            ? TemplateAttackEmulator::fromPackage([], $personaSeed, $this->config->decoySessionKey)->disable($this->config->exclude)
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

            // Path-override (WP-Phase-2): a request-aware rule may claim this path via owns_path and
            // override the static exact-store stub. Sits AFTER the M2 guard (so a live host route is
            // never shadowed) and BEFORE the route verdict; on a decline it falls through to the
            // static bundle below — zero coverage loss, no new throw path.
            if ($this->attackEmulator !== null && $this->attackEmulator->ownsPath($r->path)) {
                $ov = $this->attackEmulator->matchRule($r);
                // A persona-gated rule (e.g. the Next.js RSC responder) fires ONLY where the served
                // `/` persona is the gate's pid — personaGateAllows() reproduces the serve-path pick
                // byte-for-byte, so gate-open ⟺ this deploy actually presents that stack. A closed
                // gate is treated as a decline (fall through below), never a fleet-wide override.
                if ($ov !== null && $this->personaGateAllows($ov['rule'], $r)) {
                    $rule = $ov['rule'];
                    $detection = TemplateAttackEmulator::detectionForRule($rule);
                    $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $ov['captures']);

                    return new Verdict(
                        Verdict::ATTACK_CLASS,
                        $detection,
                        $detection->highestSeverity,
                        $anomaly,
                        $signals,
                        $handle
                    );
                }

                // Owned path, but the request-aware rule declined (a rare path/method variant the
                // rule's stricter match missed, or a closed persona gate). The static store bundle at
                // an owned login path may be the exact login-SUCCESS decoy owns_path exists to shadow
                // — never re-expose an authenticated success on a decline. Degrade to CLEAN when the
                // fallthrough entry carries an auth-success witness. A ROOT/homepage entry (all sig=1)
                // is by definition an ordinary-visitor path, never a login-success decoy, so it is
                // exempt: it must fall through to the persona lottery below (a gated owns_path rule
                // that claims `/`, like the RSC responder, would otherwise 404 the homepage on every
                // deploy whose `/` set happens to carry a session-cookie persona). A benign non-root
                // entry (a login page, no witness) still falls through to the static route verdict.
                if (!$this->isRootEntry($bundles) && $this->hasAuthSuccessWitness($bundles)) {
                    return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
                }
            }

            $detection = $this->detectionFor($key, $this->detectIds($entry));

            // Ignore-from-detection (Config->ignoreTemplates): when the host has silenced every
            // template that would have matched here, the entry carries no evidence and is no longer
            // a probe — classify CLEAN. Drop-from-evidence: an entry with any surviving match still
            // classifies below. Guarded on the set so behaviour is untouched when the feature is off.
            if ($this->ignoreTemplates !== [] && $detection->isEmpty()) {
                return new Verdict(Verdict::CLEAN, Detection::none(), '', $anomaly, $signals, null);
            }

            $handle = FakeHandle::route($key);

            // A bare root/homepage entry (all bundles sig=1) is an ordinary-visitor path: classify
            // clean natively (the probe-signature predicate is a policy input, not content). Keep
            // the handle so the policy can still synthesize when it supplies one.
            $classification = $this->isRootEntry($bundles) ? Verdict::CLEAN : Verdict::SCANNER_PROBE;

            return new Verdict($classification, $detection, $detection->highestSeverity, $anomaly, $signals, $handle);
        }

        if ($this->attackEmulator !== null) {
            // Param-route tier: a parameterized path the exact store can't key, dispatched by
            // prefix bucket. It sits BETWEEN the exact-store miss and the linear attack scan, and
            // a hit returns here — so a matched param route skips the attack gauntlet entirely. The
            // served entry is attack-rule shaped, so it rides the same ATTACK_CLASS handle + render.
            $pm = $this->attackEmulator->matchParamRoute($r);
            if ($pm !== null) {
                $rule = $pm['rule'];
                $detection = TemplateAttackEmulator::detectionForRule($rule);
                $handle = FakeHandle::attack((string) ($rule['id'] ?? 'attack'), $pm['captures']);

                return new Verdict(
                    Verdict::ATTACK_CLASS,
                    $detection,
                    $detection->highestSeverity,
                    $anomaly,
                    $signals,
                    $handle
                );
            }

            $matched = $this->attackEmulator->matchRule($r);
            // A persona-gated rule reached on a store MISS (the linear scan) is gated the same way as
            // on the owns_path override path, so a future gated rule on a store-miss path can't bypass
            // the gate via this branch. A closed gate falls through to the CLEAN verdict below (the app
            // serves its own 404). Ungated rules hit the isset() early-out in personaGateAllows() and
            // are unaffected — behaviour for every existing rule is byte-identical.
            if ($matched !== null && $this->personaGateAllows($matched['rule'], $r)) {
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
     * True when any candidate bundle's header-watch declares an authenticated-session witness
     * (a Set-Cookie / logged-in / session-id marker) — i.e. the bundle is a login-SUCCESS decoy.
     * Used to refuse re-exposing such a bundle on an owns_path override decline.
     *
     * @param array<int,array<string,mixed>> $bundles
     */
    private function hasAuthSuccessWitness(array $bundles): bool
    {
        foreach ($bundles as $bundle) {
            foreach ((array) ($bundle['hw'] ?? []) as $w) {
                $lw = strtolower((string) $w);
                if (strpos($lw, 'set-cookie') !== false
                    || strpos($lw, 'logged_in') !== false
                    || strpos($lw, 'sid=') !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * The persona gate for a request-aware owns_path rule that presents a specific stack (the
     * Next.js RSC responder, FP-0229). An UNGATED rule (no `persona_gate`) is always allowed — the
     * isset() early-out keeps every existing rule byte-identical and pays only an array-key check.
     *
     * A gated rule fires ONLY where the deploy's served `/` persona IS the gate's pid. The gate
     * REPRODUCES the serve-path pick exactly: it resolves the homepage entry, filters to servable
     * candidates with the SAME candidates() the serve path uses (buildRouteFake, so any exclude /
     * severityCeiling / nucleiReflection:false is honoured identically), and picks with the SAME
     * seedFor($r). Because seedFor is host+salt only — never path or query — the RSC request
     * (`GET /?_rsc=1`) yields the same seed as that attacker's homepage `GET /`, so the gate's pick
     * is byte-for-byte the persona that attacker is served at `/`. Therefore
     * gate-open ⟺ served-`/`-persona-is-<pid>, by construction, under any config — no raw-vs-filtered
     * divergence, no fleet-wide leak. Fail-closed on a missing entry / empty candidate set (never a
     * throw): a rule that cannot prove its stack is present simply declines.
     *
     * @param array<string,mixed> $rule
     */
    private function personaGateAllows(array $rule, RequestContext $r): bool
    {
        if (!isset($rule['persona_gate'])) {
            return true;
        }

        $resolved = $this->resolveEntry('GET', '/');
        if ($resolved === null) {
            return false;
        }

        $candidates = $this->candidates($resolved[1]['b'] ?? []);
        if ($candidates === []) {
            return false;
        }

        $picked = PersonaSelector::pick($candidates, $this->config->seedFor($r));

        return $picked !== null && ($picked['pid'] ?? null) === $rule['persona_gate'];
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
    /**
     * Whether the request looks like a top-level navigation rather than a subresource or API call.
     *
     * Reads the VALUE of sec-fetch-mode, not merely its presence. Defaults to true: an unknown
     * request shape is scored as a navigation, so nothing is suppressed without positive evidence.
     *
     * A scanner can of course claim `sec-fetch-mode: cors`. What that buys is **5 points** — the
     * Accept-Language absence, and nothing else. It cannot touch the scanner-UA, empty-UA,
     * client-hint contradiction, platform-mismatch or h2 signals.
     *
     * That bound is not free, it is enforced by two things: `$hasFetchMeta` requires the sec-fetch
     * TRIO, so a lone forged header cannot disarm the client-hint contradiction; and the mode is
     * whitelisted, so an unrecognised value scores as a navigation. An earlier version had neither,
     * and one forged header took a Chrome-UA scanner from 34 to 7.
     *
     * @param array<string,string> $h lowercased headers
     */
    private function isNavigation(array $h): bool
    {
        // Whitelist, never blacklist. sec-fetch-mode is a closed set, so an unrecognised value is
        // itself odd — treating "anything but navigate" as a subresource handed the full suppression
        // to `Sec-Fetch-Mode: banana`, which is the opposite of requiring positive evidence.
        $mode = isset($h['sec-fetch-mode']) ? strtolower(trim($h['sec-fetch-mode'])) : '';
        if ($mode !== '') {
            return !in_array($mode, array('cors', 'no-cors', 'same-origin', 'websocket'), true);
        }

        // Pre-fetch-metadata browsers and libraries: the classic AJAX marker.
        if (isset($h['x-requested-with'])
            && strtolower(trim($h['x-requested-with'])) === 'xmlhttprequest') {
            return false;
        }

        // An Accept asking only for a data format is not a page load.
        if (isset($h['accept'])) {
            $accept = strtolower(trim($h['accept']));
            if ($accept !== '' && strpos($accept, 'text/html') === false
                && strpos($accept, 'application/xhtml') === false
                && (strpos($accept, 'application/json') === 0 || strpos($accept, 'text/event-stream') === 0)) {
                return false;
            }
        }

        return true;
    }

    private function botSignals(RequestContext $r): BotSignalSet
    {
        $h = $this->lowercaseHeaders($r->headers);
        $ua = isset($h['user-agent']) ? trim($h['user-agent']) : '';
        $uaClass = $this->classifyUserAgent($ua);

        $flags = [];
        $weight = 0;

        // Is this a top-level navigation, or a subresource/API call the page made?
        //
        // Browsers send a different header set for each. Accept-Language and a document-shaped
        // Accept belong to a navigation; on fetch/XHR Chrome omits the former and sends `*/*` for
        // the latter. Scoring their absence unconditionally charged every AJAX call on a JS-heavy
        // site — measured at anomaly 5 for a plain XHR and 17 for a bare fetch(), from the same
        // browser that scored 0 on the navigation a moment earlier.
        //
        // Suppressed, not merely re-weighted: on a non-navigation these headers are irrelevant
        // rather than weak evidence, and a smaller weight still accumulates across a page's worth
        // of requests.
        $navigation = $this->isNavigation($h);

        // Header presence — the coarsest signal.
        if (!isset($h['accept'])) {
            $flags[BotSignalSet::MISSING_ACCEPT] = true;
            $weight += 5;
        }
        if ($navigation && !isset($h['accept-language'])) {
            $flags[BotSignalSet::MISSING_ACCEPT_LANGUAGE] = true;
            $weight += 5;
        }
        // NOT suppressed on a subresource: Accept-Encoding is a forbidden header name, so the
        // browser sets it on fetch/XHR exactly as on a navigation. Unlike Accept-Language it is
        // never legitimately absent, and the XHR false positive this change fixed was 5 points of
        // Accept-Language alone.
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
        // The TRIO, not any one header. A real browser sends sec-fetch-site, -mode and -dest
        // together on both navigations and subresources (only -user is navigation-only). Accepting
        // any single header let one forged `Sec-Fetch-Mode: cors` disarm the 15-point client-hint
        // contradiction below — measured, that took a Chrome-UA scanner from 34 to 7.
        $hasFetchMeta = isset($h['sec-fetch-site']) && isset($h['sec-fetch-mode'])
            && isset($h['sec-fetch-dest']);
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
        // No UA class is exempt. A crawler claim is an unverified string anyone can send, so
        // exempting it here would sell this signal for the price of one appended word. Forgiving a
        // real crawler is the host's call, after the reverse-DNS check core cannot perform.
        if ($claimsChromium && !$hasClientHints && !$hasFetchMeta) {
            $flags[BotSignalSet::UA_CLAIMS_BROWSER_NO_HINTS] = true;
            $weight += 15;
        }
        // `*/*` is what fetch() sends by default, so it is normal for a subresource and odd only
        // for a navigation.
        if ($navigation && $claimsBrowser && isset($h['accept']) && trim($h['accept']) === '*/*') {
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

        $host = $r->host !== '' ? $r->host : (isset($h['host']) ? $h['host'] : '');
        if ($this->isBareIpHost($host)) {
            $flags[BotSignalSet::HOST_IS_BARE_IP] = true;
            $weight += 10;
        }

        return new BotSignalSet($flags, $weight, $uaClass, $this->structuralFingerprint($r->headers));
    }

    /**
     * True when the host header / request host is an IP literal rather than a domain name.
     */
    private function isBareIpHost(string $host): bool
    {
        $host = trim($host);
        if ($host === '') {
            return false;
        }

        // Direct IP check: covers raw IPv4 ('203.0.113.7') and unbracketed IPv6 ('2001:db8::1', '::1')
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        // Bracketed IPv6, with optional port: '[2001:db8::1]' or '[2001:db8::1]:443'
        if ($host[0] === '[') {
            $close = strrpos($host, ']');
            if ($close !== false) {
                $ip = substr($host, 1, $close - 1);
                $rest = substr($host, $close + 1);
                if ($rest === '' || preg_match('/^:\d+$/', $rest) === 1) {
                    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
                }
            }

            return false;
        }

        // IPv4 with port: '203.0.113.7:8080'
        if (substr_count($host, ':') === 1) {
            $parts = explode(':', $host, 2);
            if (preg_match('/^\d+$/', $parts[1]) === 1) {
                return filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
            }
        }

        return false;
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
        // Attack tools ONLY. This class is the one that acts without an opt-in, so an ordinary
        // HTTP client (python-httpx) or a commercial crawler (SemrushBot) must never be listed
        // here — they belong in the script and good-bot classes below.
        if (preg_match('/nmap|sqlmap|nuclei|nikto|masscan|zgrab|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|feroxbuster|arachni|zaproxy/i', $ua) === 1) {
            return BotSignalSet::UA_SCANNER;
        }
        if (preg_match('#curl|wget|python-requests|python-urllib|python-httpx|urllib|go-http-client|libwww|okhttp|axios|node-fetch|guzzle|java/|apache-httpclient|ruby|perl|winhttp#i', $ua) === 1) {
            return BotSignalSet::UA_SCRIPT;
        }
        // Checked after scanner and script: a tool claiming to be Googlebot is a tool. Checked
        // before the browser test because most crawler UAs also contain "Mozilla".
        if (preg_match(
            '/googlebot|bingbot|slurp|duckduckbot|baiduspider|yandex(bot|images|mobile)|'
            . 'applebot|facebookexternalhit|twitterbot|linkedinbot|pinterest(bot)?|'
            . 'discordbot|telegrambot|whatsapp|slackbot|redditbot|petalbot|seznambot|semrushbot/i',
            $ua
        ) === 1) {
            return BotSignalSet::UA_GOOD_BOT;
        }

        // The `Mozilla/` prefix, not a substring: real browsers and every major crawler UA start
        // with it, while an unknown tool merely containing "mozilla" is not a browser.
        if (strncasecmp($ua, 'Mozilla/', 8) === 0) {
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

        $built = $this->buildFake($verdict->fakeHandle, SiteProfile::empty(), $seed, $r);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        if (!$this->observer->shouldRespond($r, $verdict->detection)) {
            return $this->declined($r, Outcome::VETOED);
        }

        // Surface the winning handle to the app (debug tooling). Inert: never emitted (see
        // SynthesizedResponse::$servedBy).
        $built['r']->servedBy = $handle;

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

        $built = $this->buildFake($verdict->fakeHandle, SiteProfile::empty(), $seed, $r);
        if ($built['r'] === null) {
            return $this->declined($r, $built['reason']);
        }

        // Surface the winning handle to the app (debug tooling). Inert: never emitted (see
        // SynthesizedResponse::$servedBy).
        $built['r']->servedBy = $verdict->fakeHandle;

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
        return $this->buildFake($verdict->fakeHandle, $profile, $seed)['r'];
    }

    public function synthesizeFromHandle(?FakeHandle $handle, SiteProfile $profile, string $seed): ?SynthesizedResponse
    {
        return $this->buildFake($handle, $profile, $seed)['r'];
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
     * $r is the live request, threaded ONLY on the facade path (respond) so a behavior primitive
     * can consult it; the position-blind port (synthesize) leaves it null and any request-aware
     * behavior degrades to its request-free default. It never affects route/persona synthesis.
     *
     * @return array{r:?SynthesizedResponse,reason:string}
     */
    private function buildFake(?FakeHandle $handle, SiteProfile $profile, string $seed, ?RequestContext $r = null): array
    {
        if ($handle === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }
        if ($handle->kind === FakeHandle::KIND_ROUTE) {
            $built = $this->buildRouteFake($handle, $profile, $seed);
        } elseif ($handle->kind === FakeHandle::KIND_ATTACK) {
            $built = $this->buildAttackFake($handle, $seed, $r);
        } else {
            // Unknown / llm kinds are host-injected synthesizers; core builds nothing.
            return ['r' => null, 'reason' => Outcome::UNSYNTHESIZABLE];
        }

        // Single convergence point: every served fake gets the same front-layer envelope, so the
        // route (synthesizer) path and the attack-template path are indistinguishable by it. Without
        // this, attack fakes shipped no X-Request-Id and its absence marked the branch as canned.
        if ($built['r'] !== null) {
            $this->stampEnvelope($built['r']);
        }

        return $built;
    }

    /**
     * Stamp the cosmetic front-layer headers a real proxy/app adds to every response: a
     * per-request X-Request-Id (16 hex, like a real edge) plus the deploy's coherent Server /
     * X-Powered-By identity. Each is guarded so a value the synthesizer or an emulator already set
     * is never overwritten — the route path stamps these itself, so this only fills the attack-
     * template path (and any future branch) without double-stamping. Pure hex is CR/LF/NUL-safe,
     * so X-Request-Id never trips the C8 header guard.
     */
    private function stampEnvelope(SynthesizedResponse $response): void
    {
        $headers = $response->headers;

        if ($this->config->serverHeader !== null && !isset($headers['Server'])) {
            $headers['Server'] = $this->config->serverHeader;
        }
        if ($this->config->poweredBy !== null && !isset($headers['X-Powered-By'])) {
            $headers['X-Powered-By'] = $this->config->poweredBy;
        }
        if (!isset($headers['X-Request-Id'])) {
            $headers['X-Request-Id'] = bin2hex(random_bytes(8));
        }

        $response->headers = $headers;
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
    private function buildAttackFake(FakeHandle $handle, string $seed, ?RequestContext $r = null): array
    {
        if ($this->attackEmulator === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        $rule = $this->attackEmulator->ruleById((string) $handle->ruleId);
        if ($rule === null) {
            return ['r' => null, 'reason' => Outcome::NO_CANDIDATE];
        }

        // A decoy that reflects attacker request bytes into an active context (an HTML body or a
        // redirect Location) is safe bait only from an isolated origin; inline in a response-owning
        // host it would be a live XSS/open-redirect in that host's real origin. classify() already
        // ran, so the detection/intel is captured — this only withholds the reflection. Covers both
        // the attack tier and the param tier: a matched param route rides an attack handle and
        // ruleById() resolves param entries here too.
        if (!$this->config->isolatedOrigin && !empty($rule['reflects_input'])) {
            return ['r' => null, 'reason' => Outcome::REFLECTION_SUPPRESSED];
        }

        // Seed fake values from the persona so a given attacker sees stable, but per-attacker
        // distinct, fabricated secrets (not one shared seed-0 value that would fingerprint). $r is
        // present only on the facade path; the port leaves it null (behavior renders its default).
        $response = $this->attackEmulator->renderRule($rule, $handle->captures, crc32($seed), $r);
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
            return $this->applyIgnore($entry['d']);
        }

        $ids = [];
        foreach ($entry['b'] ?? [] as $bundle) {
            foreach ($bundle['t'] ?? [] as $id) {
                $ids[] = $id;
            }
        }

        return $this->applyIgnore($ids);
    }

    /**
     * Drop template ids the host has marked ignore-from-detection (Config->ignoreTemplates): an id
     * named directly, or one whose template carries an ignored tag. Detection-only — it never
     * changes which bundles are served (that is Config->exclude's separate job). When the set is
     * empty the list is returned unchanged, so a host that does not use the feature pays nothing.
     *
     * Drop-from-evidence: an ignored id simply contributes no evidence; any remaining id still
     * drives the detection. classify() reads the emptied result and degrades that entry to CLEAN.
     *
     * @param string[] $ids
     * @return string[]
     */
    private function applyIgnore(array $ids): array
    {
        if ($this->ignoreTemplates === []) {
            return $ids;
        }

        $kept = [];
        foreach ($ids as $id) {
            if (isset($this->ignoreTemplates[$id])) {
                continue;
            }
            $meta = $this->store->template($id);
            $byTag = false;
            foreach ((array) ($meta['tags'] ?? []) as $tag) {
                if (isset($this->ignoreTemplates[$tag])) {
                    $byTag = true;
                    break;
                }
            }
            if (!$byTag) {
                $kept[] = $id;
            }
        }

        return $kept;
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
