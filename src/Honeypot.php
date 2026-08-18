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

    public function detect(RequestContext $r): Detection
    {
        $resolved = $this->resolveEntry($r->method, $r->path);
        if ($resolved === null) {
            return Detection::none();
        }
        [$key, $entry] = $resolved;

        $detection = $this->detectionFor($key, $this->detectIds($entry));

        return $detection->isEmpty() ? Detection::none() : $detection;
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

    public function respond(RequestContext $r): ?SynthesizedResponse
    {
        // Ground-truth switches first: a tripped kill switch or a trusted scanner must
        // NEVER see a fake, and respond mode must be explicitly enabled.
        if ($this->config->killSwitchTripped()) {
            return null;
        }
        if (!$this->config->respondEnabled()) {
            return null;
        }
        if ($this->config->isTrusted($r)) {
            return null;
        }

        // matched-only guarantee: a miss returns null so the app serves its real 404 —
        // unless an injection payload is present and attack emulation is on.
        $resolved = $this->resolveEntry($r->method, $r->path);
        if ($resolved === null) {
            return $this->tryAttack($r);
        }
        [$key, $entry] = $resolved;

        $allBundles = $entry['b'] ?? [];
        if ($allBundles === []) {
            return null;
        }

        // Detection covers EVERY routed template — the probe matched them regardless of
        // what we choose to serve (on a capped key that is the full 'd' id-list, wider
        // than the served 'b' set). Signal the app before any serve decision.
        $detection = $this->detectionFor($key, $this->detectIds($entry));
        $this->observer->onDetection($r, $detection);

        if (!$this->config->gateOpen($r)) {
            return $this->declined($r, Outcome::GATE_CLOSED);
        }

        // Filter to servable candidates BEFORE the persona pick: excluded bundles and
        // bundles above the severity ceiling are removed so a seed never lands on a
        // refused bundle and leaves a coverage hole.
        $candidates = $this->candidates($allBundles);
        if ($candidates === []) {
            return $this->declined($r, Outcome::NO_CANDIDATE);
        }

        $bundle = PersonaSelector::pick($candidates, $this->config->seedFor($r));
        if ($bundle === null) {
            return $this->declined($r, Outcome::NO_CANDIDATE);
        }

        // Root / homepage-class entries never fake-vuln ordinary visitors.
        if ((int) ($bundle['sig'] ?? 0) === 1 && !$this->config->hasProbeSignature($r)) {
            return $this->declined($r, Outcome::NO_SIGNATURE);
        }

        if (!$this->observer->shouldRespond($r, $detection)) {
            return $this->declined($r, Outcome::VETOED);
        }

        $satisfies = $this->detectionFor($key, $bundle['t'] ?? []);
        $response = $this->synthesizer->synthesize($bundle, $satisfies, $this->config->seedFor($r));
        if ($response === null) {
            return $this->declined($r, Outcome::UNSYNTHESIZABLE);
        }

        // Never emit an oversized body (no tarpit/amplifier unless the app opts in).
        if (strlen($response->body) > $this->config->maxBodyBytes) {
            return $this->declined($r, Outcome::OVER_CAP);
        }

        // Pause (base + random jitter) so responses aren't the instant, uniform sub-ms
        // replies that fingerprint a honeypot. No-op when both latency knobs are 0.
        $delay = $this->config->serveDelayMicros();
        if ($delay > 0) {
            usleep($delay);
        }

        $this->observer->onOutcome($r, $response, Outcome::SERVED);

        return $response;
    }

    private function declined(RequestContext $r, string $reason): ?SynthesizedResponse
    {
        $this->observer->onOutcome($r, null, $reason);

        return null;
    }

    /**
     * When no template routes, try interactive attack-class emulation on the request's
     * payload (LFI/SQLi/SSTI/command-injection/reflected-XSS). Only runs when opted in;
     * reached only after the kill-switch, mode, and trusted-bypass checks. Honours the
     * severity ceiling (fake RCE stays off by default) and the body-size cap.
     */
    private function tryAttack(RequestContext $r): ?SynthesizedResponse
    {
        if ($this->attackEmulator === null) {
            return null;
        }

        // Seed fake values from the persona so a given attacker sees stable, but per-attacker
        // distinct, fabricated secrets (not one shared seed-0 value that would fingerprint).
        $attack = $this->attackEmulator->emulate($r, crc32($this->config->seedFor($r)));
        if ($attack === null) {
            return null;
        }

        $this->observer->onDetection($r, $attack->satisfies);

        if (Severity::exceeds($attack->satisfies->highestSeverity, $this->config->severityCeiling)) {
            return $this->declined($r, Outcome::NO_CANDIDATE);
        }
        if (strlen($attack->body) > $this->config->maxBodyBytes) {
            return $this->declined($r, Outcome::OVER_CAP);
        }

        $delay = $this->config->serveDelayMicros();
        if ($delay > 0) {
            usleep($delay);
        }

        $this->observer->onOutcome($r, $attack, Outcome::SERVED);

        return $attack;
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
