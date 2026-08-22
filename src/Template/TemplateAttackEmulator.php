<?php

declare(strict_types=1);

namespace Funnypot\Template;

use Funnypot\Behavior\NullEphemeralStore;
use Funnypot\Behavior\SystemClock;
use Funnypot\Contracts\Clock;
use Funnypot\Contracts\EphemeralStore;
use Funnypot\Detection;
use Funnypot\RequestContext;
use Funnypot\Response\EmulatedContent;
use Funnypot\Rules\RulesLocator;
use Funnypot\SynthesizedResponse;
use Funnypot\TemplateMatch;

/**
 * Data-driven attack emulation. Interprets compiled attack rules (from funnypot templates)
 * against a request — the same job the hand-coded Attack\Signature classes did, but every
 * emulation is now data. First rule whose match conditions all hold wins; its response is
 * rendered through the bounded DirectiveRenderer and served.
 *
 * Runtime is PHP-only: rules are a frozen PHP array (compiled from YAML at build time).
 */
final class TemplateAttackEmulator
{
    /** @var DirectiveRenderer */
    private $renderer;

    /** @var array<string,true> rule ids the operator has switched off */
    private $disabled = [];

    /** @var array<int,array<string,mixed>> compiled attack rules */
    private $rules;

    /**
     * Compiled param-route buckets: `['schema'=>1,'buckets'=>['<seg>'=>[<entry...>]]]`. A
     * parameterized path can't be keyed in the exact store, so it dispatches here — between the
     * exact-store miss and the linear attack scan. Empty (`[]`) when no artifact is installed, so
     * a host without one behaves byte-identically.
     *
     * @var array<string,mixed>
     */
    private $paramBuckets;

    /** @var array<string,string> operator tripwire tokens */
    private $canary;

    /** @var Clock time source for behavior primitives that need the wall clock */
    private $clock;

    /** @var EphemeralStore per-actor scratch space for behavior primitives */
    private $store;

    /**
     * Named behavior primitives, keyed by the rule's `behavior` value. Each is a closure over
     * $this that turns a behavior config + captures into an EmulatedContent (or null to fall back
     * to the rule's base response). `default` is not a name here — an absent/unknown behavior is
     * simply the plain render. `branch` and `traversal-read` exist; the other primitives are deferred.
     *
     * @var array<string,callable>
     */
    private $behaviors;

    /**
     * @param array<int,array<string,mixed>> $rules        compiled attack rules
     * @param array<string,string>           $canary       operator tripwire tokens
     * @param array<string,mixed>            $paramBuckets compiled param-route bucket index ([] = none)
     */
    public function __construct(
        array $rules,
        array $canary = [],
        ?Clock $clock = null,
        ?EphemeralStore $store = null,
        array $paramBuckets = []
    ) {
        $this->rules = $rules;
        $this->canary = $canary;
        $this->paramBuckets = $paramBuckets;
        $this->renderer = new DirectiveRenderer();
        $this->clock = $clock ?? new SystemClock();
        $this->store = $store ?? new NullEphemeralStore();
        $this->behaviors = [
            'branch' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleBranch($config, $captures, $r, $seed);
            },
            // Position-blind: reads only the reflected `path` capture, so it renders the same on the
            // facade (respond) and the port (synthesize) — $r/clock/store are unused.
            'traversal-read' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleTraversalRead($config, $captures, $seed);
            },
        ];
    }

    /** @param array<string,string> $canary */
    public static function fromFile(string $path, array $canary = []): self
    {
        $rules = is_file($path) ? require $path : [];

        return new self(is_array($rules) ? $rules : [], $canary, null, null, self::loadParamBuckets());
    }

    /**
     * The compiled param-route index, from a RulesUpdater-managed copy under the data dir when
     * present else the packaged copy (RulesLocator decides). Absent → [] so a host without the
     * artifact is byte-identical to before this tier existed.
     *
     * @return array<string,mixed>
     */
    private static function loadParamBuckets(): array
    {
        $path = RulesLocator::resolve('funnypot-param.php');
        if (!is_file($path)) {
            return [];
        }
        $buckets = require $path;

        return is_array($buckets) ? $buckets : [];
    }

    /**
     * Build against the attack rules — a RulesUpdater-managed copy under the configured data
     * dir when present, else the copy compiled into the package (RulesLocator decides).
     */
    public static function fromPackage(array $canary = []): self
    {
        return self::fromFile(RulesLocator::resolve('funnypot-attack.php'), $canary);
    }

    /**
     * Restrict to the operator's enabled set — rule ids in $disabled are skipped, so a vuln
     * switched off in the emulation catalog is never served. Fluent for construction.
     *
     * @param string[] $disabledIds
     */
    public function disable(array $disabledIds): self
    {
        foreach ($disabledIds as $id) {
            $this->disabled[$id] = true;
        }

        return $this;
    }

    public function emulate(RequestContext $r, int $seed = 0): ?SynthesizedResponse
    {
        $matched = $this->matchRule($r);
        if ($matched === null) {
            return null;
        }

        return $this->renderRule($matched['rule'], $matched['captures'], $seed, $r);
    }

    /**
     * The match half of emulate(), render-free — so classify() can recognize an attack class
     * (and capture the ruleId + reflected groups) without building a body. First enabled rule
     * whose conditions all hold wins.
     *
     * @return array{rule:array<string,mixed>,captures:array<int|string,string>}|null
     */
    public function matchRule(RequestContext $r): ?array
    {
        foreach ($this->rules as $rule) {
            if ($this->disabled !== [] && isset($this->disabled[(string) ($rule['id'] ?? '')])) {
                continue;
            }
            // Cheap literal pre-filter: the compiler proves `lit` is a substring every match of
            // this rule must carry in surface `lit_in`. If it is absent, no condition can hold —
            // skip the regex loop. Pure speedup: rules without `lit` are evaluated as before, and
            // a present literal only means "evaluate", never "match".
            if (isset($rule['lit']) && $this->literalAbsent($r, $rule)) {
                continue;
            }
            $captures = $this->match($r, $rule);
            if ($captures === null) {
                continue;
            }

            return ['rule' => $rule, 'captures' => $captures];
        }

        return null;
    }

    /**
     * The param-route tier: match a parameterized path (e.g. `/@fs/{path}`) that the exact store
     * can't key, BETWEEN the exact-store miss and the linear attack scan. The request's first path
     * segment selects one prefix bucket via a single hash probe — a miss returns null immediately,
     * cheaper than the linear scan — then a bounded loop over that bucket's compiler-authored,
     * anchored regexes runs (no attacker regex, so no ReDoS). First enabled entry that matches wins.
     *
     * @return array{rule:array<string,mixed>,captures:array<int|string,string>}|null
     */
    public function matchParamRoute(RequestContext $r): ?array
    {
        $buckets = $this->paramBuckets['buckets'] ?? null;
        if (!is_array($buckets) || $buckets === []) {
            return null;
        }
        $seg = $this->firstPathSegment($r->path);
        if ($seg === '' || !isset($buckets[$seg]) || !is_array($buckets[$seg])) {
            return null;
        }

        $path = $r->path;
        if (strlen($path) > self::MAX_SURFACE) {
            $path = substr($path, 0, self::MAX_SURFACE);
        }
        foreach ($buckets[$seg] as $entry) {
            if ($this->disabled !== [] && isset($this->disabled[(string) ($entry['id'] ?? '')])) {
                continue;
            }
            $regex = (string) ($entry['regex'] ?? '');
            if ($regex === '') {
                continue;
            }
            if (preg_match('~' . $regex . '~', $path, $m) === 1 && preg_last_error() === PREG_NO_ERROR) {
                return ['rule' => $entry, 'captures' => $m];
            }
        }

        return null;
    }

    /** The first '/'-delimited segment of a request path (the param-bucket key), leading slash folded. */
    private function firstPathSegment(string $path): string
    {
        if ($path !== '' && $path[0] === '/') {
            $path = substr($path, 1);
        }
        $slash = strpos($path, '/');

        return $slash === false ? $path : substr($path, 0, $slash);
    }

    /**
     * The render half of emulate(): turn a matched rule + its captures into a response. Returns
     * null when a rendered header would carry CR/LF/NUL (the C8 header-splitting guard). Kept
     * separate so synthesize() can render a rule the Verdict already named.
     *
     * A rule may name a `behavior` primitive; when it does and the primitive is registered, the
     * primitive picks the response content, else the rule's base `response` renders. The request
     * is available only on the facade path (respond) — the position-blind port (synthesize) leaves
     * $r null, so a behavior that needs the request degrades to its request-free default there.
     *
     * All response envelope concerns are centralized HERE, never in a behavior handler: the empty
     * Content-Type default, the single C8 header-splitting guard, and the app-chosen status (a
     * behavior may only override it via EmulatedContent::$status — never the header set or C8).
     *
     * @param array<string,mixed>          $rule
     * @param array<int|string,string>     $captures
     */
    public function renderRule(array $rule, array $captures, int $seed, ?RequestContext $r = null): ?SynthesizedResponse
    {
        $behavior = isset($rule['behavior']) ? (string) $rule['behavior'] : '';
        $content = null;
        if ($behavior !== '' && isset($this->behaviors[$behavior])) {
            $handler = $this->behaviors[$behavior];
            $content = $handler((array) ($rule[$behavior] ?? []), $captures, $r, $seed, $this->clock, $this->store);
        }
        if ($content === null) {
            $content = $this->defaultRender($rule, $captures, $seed);
        }

        $headers = $content->headers;
        if ($headers === []) {
            $headers = ['Content-Type' => 'text/plain; charset=utf-8'];
        }

        // C8: a rendered header value (e.g. a reflected redirect Location) must not carry
        // CR/LF/NUL. If it does, decline this rule (no header splitting).
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1 || preg_match('/[\r\n\x00]/', $value) === 1) {
                return null;
            }
        }

        // Status is always app-chosen: a behavior may name one via EmulatedContent::$status, else
        // the rule's own status. Never model/attacker-chosen (no open redirect via a fabricated 3xx).
        $status = $content->status ?? (int) ($rule['status'] ?? 200);

        return new SynthesizedResponse($status, $headers, $content->body, self::detectionForRule($rule));
    }

    /**
     * The plain render: the rule's base `response` body + headers through the bounded renderer.
     * The ultimate fallback when no behavior is named, or a behavior declines. Byte-for-byte the
     * render every non-behavior rule has always produced.
     *
     * @param array<string,mixed>      $rule
     * @param array<int|string,string> $captures
     */
    private function defaultRender(array $rule, array $captures, int $seed): EmulatedContent
    {
        return $this->renderResponse((array) ($rule['response'] ?? []), $captures, $seed);
    }

    /**
     * Render one authored `response` (body + headers) through the bounded renderer into an
     * EmulatedContent. Envelope concerns (CT default, C8, status precedence) are the caller's —
     * this only fills directives. An optional $status rides through so a behavior branch can pick
     * a per-case status.
     *
     * @param array<string,mixed>      $response
     * @param array<int|string,string> $captures
     */
    private function renderResponse(array $response, array $captures, int $seed, ?int $status = null): EmulatedContent
    {
        $body = $this->renderer->render((string) ($response['body'] ?? ''), $captures, $seed, $this->canary);

        $headers = [];
        foreach ((array) ($response['headers'] ?? []) as $name => $value) {
            $headers[(string) $name] = $this->renderer->render((string) $value, $captures, $seed, $this->canary);
        }

        return new EmulatedContent($body, $headers, $status);
    }

    /**
     * The `branch` behavior primitive: pick the first case whose `when` condition holds against the
     * live request and render that case's `response`; else the `default` case's response when the
     * rule authors one; else null so renderRule falls back to the rule's base response. When no
     * request is available (the position-blind port), no case can be evaluated — the default (or
     * base) is served, so the primitive degrades safely off the facade path.
     *
     * @param array<string,mixed>      $config   the rule's `branch` config (`cases` + optional `default`)
     * @param array<int|string,string> $captures reflected capture groups from the top-level match
     */
    private function handleBranch(array $config, array $captures, ?RequestContext $r, int $seed): ?EmulatedContent
    {
        if ($r !== null) {
            foreach ((array) ($config['cases'] ?? []) as $case) {
                if (!isset($case['when'])) {
                    continue;
                }
                if ($this->evalConditions($r, [$case['when']]) !== null) {
                    return $this->renderCaseResponse((array) ($case['response'] ?? []), $captures, $seed);
                }
            }
        }

        if (isset($config['default']['response'])) {
            return $this->renderCaseResponse((array) $config['default']['response'], $captures, $seed);
        }

        return null;
    }

    /**
     * Render a branch case (or default) response, carrying its optional per-case status.
     *
     * @param array<string,mixed>      $response
     * @param array<int|string,string> $captures
     */
    private function renderCaseResponse(array $response, array $captures, int $seed): EmulatedContent
    {
        $status = isset($response['status']) ? (int) $response['status'] : null;

        return $this->renderResponse($response, $captures, $seed, $status);
    }

    /**
     * The `traversal-read` behavior primitive: emulate a bounded arbitrary-file-read. The reflected
     * `path` capture is canonicalized purely in-string (NO filesystem access whatsoever), then matched
     * against the rule's authored `allow` list in order; the first hit renders its `content` (a
     * believable inert file), else the optional `default.content`, else null so renderRule falls back
     * to the rule's base `response` (the not-found body). A hit's status defaults to 200 so it never
     * inherits the base 404 — the point is that the "file" was served.
     *
     * INVARIANT: this handler and its canonicalizer touch only strings. There is no path that reads,
     * stats, or resolves a real file; every served byte is pure synthesis.
     *
     * @param array<string,mixed>      $config   the rule's `traversal-read` config (`allow` + optional `default`)
     * @param array<int|string,string> $captures reflected capture groups (uses only `path`)
     */
    private function handleTraversalRead(array $config, array $captures, int $seed): ?EmulatedContent
    {
        $raw = (string) ($captures['path'] ?? '');
        $canon = $this->canonicalizeTraversalPath($raw);

        foreach ((array) ($config['allow'] ?? []) as $entry) {
            if (is_array($entry) && $this->traversalEntryMatches($canon, $entry)) {
                return $this->renderTraversalContent((array) ($entry['content'] ?? []), $captures, $seed);
            }
        }

        if (isset($config['default']['content'])) {
            return $this->renderTraversalContent((array) $config['default']['content'], $captures, $seed);
        }

        return null;
    }

    /**
     * Canonicalize a captured file path to a relative segment path — a LOCAL normalizer, string-only.
     * NOT Support\PathNormalizer (which preserves `..`/case for routing): here `..` is resolved so an
     * allow entry can match on the real target. Decoded once, capped, then `.`/empty segments dropped
     * and `..` popped (floored at the root) in a loop bounded by MAX_TRAVERSAL_SEGMENTS.
     */
    private function canonicalizeTraversalPath(string $raw): string
    {
        $path = rawurldecode($raw);
        if (strlen($path) > self::MAX_SURFACE) {
            $path = substr($path, 0, self::MAX_SURFACE);
        }
        if ($path !== '' && $path[0] === '/') {
            $path = substr($path, 1);
        }

        $out = [];
        $i = 0;
        foreach (explode('/', $path) as $seg) {
            if (++$i > self::MAX_TRAVERSAL_SEGMENTS) {
                break;
            }
            if ($seg === '' || $seg === '.') {
                continue;
            }
            if ($seg === '..') {
                array_pop($out); // floor at the root: pop on empty is a no-op
                continue;
            }
            $out[] = $seg;
        }

        return implode('/', $out);
    }

    /**
     * Does one allow entry match the canonical path? Exactly one of `suffix` or `basename`:
     *  - `suffix`  matches on a SEGMENT boundary: the whole path equals it, or the path ends with
     *              '/'.suffix. So `.env` never matches `sentry.env`, nor `etc/passwd` `etc/xpasswd`.
     *  - `basename` matches the final path segment exactly.
     *
     * @param array<string,mixed> $entry
     */
    private function traversalEntryMatches(string $canon, array $entry): bool
    {
        if (isset($entry['suffix'])) {
            $suffix = (string) $entry['suffix'];
            if ($suffix === '') {
                return false;
            }
            if ($canon === $suffix) {
                return true;
            }
            $needle = '/' . $suffix;

            return strlen($canon) > strlen($needle) - 1
                && substr($canon, -strlen($needle)) === $needle;
        }
        if (isset($entry['basename'])) {
            $basename = (string) $entry['basename'];
            if ($basename === '') {
                return false;
            }
            $slash = strrpos($canon, '/');
            $last = $slash === false ? $canon : substr($canon, $slash + 1);

            return $last === $basename;
        }

        return false;
    }

    /**
     * Render a traversal-read `content` (body + headers + optional status) through the bounded
     * renderer. Status defaults to 200 (a hit served the "file"), never the base rule's not-found.
     *
     * @param array<string,mixed>      $content
     * @param array<int|string,string> $captures
     */
    private function renderTraversalContent(array $content, array $captures, int $seed): EmulatedContent
    {
        $status = isset($content['status']) ? (int) $content['status'] : 200;

        return $this->renderResponse($content, $captures, $seed, $status);
    }

    /**
     * Look up an enabled-or-not rule by id, for synthesize() rendering a Verdict's attack handle.
     *
     * @return array<string,mixed>|null
     */
    public function ruleById(string $id): ?array
    {
        foreach ($this->rules as $rule) {
            if ((string) ($rule['id'] ?? '') === $id) {
                return $rule;
            }
        }
        // Param entries share this id-space (the compiler enforces uniqueness across both sets),
        // so buildAttackFake's re-lookup of a param-tier hit resolves here too.
        foreach ((array) ($this->paramBuckets['buckets'] ?? []) as $entries) {
            foreach ((array) $entries as $entry) {
                if ((string) ($entry['id'] ?? '') === $id) {
                    return $entry;
                }
            }
        }

        return null;
    }

    /**
     * The Detection a matched attack rule satisfies — the single source of the attack match
     * shape shared by classify() and the render half.
     *
     * @param array<string,mixed> $rule
     */
    public static function detectionForRule(array $rule): Detection
    {
        $id = (string) ($rule['id'] ?? 'attack');
        $severity = (string) ($rule['severity'] ?? 'high');

        return new Detection(
            true,
            [new TemplateMatch($id, $severity, array_map('strval', (array) ($rule['tags'] ?? [])), $id)],
            $id,
            $severity
        );
    }

    /** Attacker-controlled surfaces are capped before regex to bound catastrophic backtracking. */
    private const MAX_SURFACE = 32768;

    /** Upper bound on segments the traversal-read canonicalizer walks — bounds the resolve loop. */
    private const MAX_TRAVERSAL_SEGMENTS = 4096;

    /**
     * The literal pre-filter test for matchRule(): is the rule's required literal absent from the
     * surface it applies to? The surface is built and capped exactly as match() does, so a literal
     * absent here is absent from what the conditions would actually scan.
     *
     * @param array<string,mixed> $rule with a 'lit' key
     */
    private function literalAbsent(RequestContext $r, array $rule): bool
    {
        $surface = $this->surface($r, (string) ($rule['lit_in'] ?? 'request'));
        if (strlen($surface) > self::MAX_SURFACE) {
            $surface = substr($surface, 0, self::MAX_SURFACE);
        }
        $lit = (string) $rule['lit'];
        $ci = ($rule['lit_ci'] ?? true) !== false;
        $hit = $ci ? stripos($surface, $lit) : strpos($surface, $lit);

        return $hit === false;
    }

    /**
     * Match all of a rule's conditions (AND). Returns the capture groups used by {{match.N}} —
     * the groups of the condition marked `capture: true`, else the first regex condition's —
     * or an empty array when matched with no captures, or null when any condition fails.
     *
     * @param array<string,mixed> $rule
     * @return array<int|string,string>|null
     */
    private function match(RequestContext $r, array $rule): ?array
    {
        return $this->evalConditions($r, (array) ($rule['match'] ?? []));
    }

    /**
     * Evaluate an AND-list of conditions against the request. Returns the capture groups used by
     * {{match.N}} — the groups of the condition marked `capture: true`, else the first regex
     * condition's — or an empty array when matched with no captures, or null when any condition
     * fails. The condition vocabulary and cap/ci/PCRE-error-fails-safe semantics are shared by the
     * top-level rule match and the `branch` primitive's per-case `when`.
     *
     * @param array<int,array<string,mixed>> $conds
     * @return array<int|string,string>|null
     */
    private function evalConditions(RequestContext $r, array $conds): ?array
    {
        $captures = null;
        foreach ($conds as $cond) {
            $surface = $this->surface($r, (string) ($cond['in'] ?? 'request'));
            if (strlen($surface) > self::MAX_SURFACE) {
                $surface = substr($surface, 0, self::MAX_SURFACE);
            }
            $ci = ($cond['ci'] ?? true) !== false;

            if (isset($cond['regex'])) {
                $flags = ($ci ? 'i' : '') . (($cond['dotall'] ?? false) ? 's' : '');
                $result = preg_match('~' . $cond['regex'] . '~' . $flags, $surface, $m);
                // A PCRE error (false / backtrack limit) is a bad authored pattern, not a hit:
                // fail the whole rule so a broken template can never emulate.
                if ($result !== 1 || preg_last_error() !== PREG_NO_ERROR) {
                    return null;
                }
                if ($captures === null || ($cond['capture'] ?? false) === true) {
                    $captures = $m;
                }
            } elseif (isset($cond['contains'])) {
                $needle = (string) $cond['contains'];
                $hit = $ci ? stripos($surface, $needle) : strpos($surface, $needle);
                if ($hit === false) {
                    return null;
                }
            } else {
                return null;
            }
        }

        return $captures ?? [];
    }

    private function surface(RequestContext $r, string $in): string
    {
        if (strncmp($in, 'header:', 7) === 0) {
            $name = substr($in, 7);
            foreach ($r->headers as $key => $value) {
                if (strcasecmp((string) $key, $name) === 0) {
                    return (string) $value;
                }
            }

            return '';
        }

        switch ($in) {
            case 'header':
            case 'headers':
                return implode(' ', array_map('strval', $r->headers));
            case 'path':
                return $r->path;
            case 'query':
                return $r->query;
            case 'method':
                // The HTTP verb, so a rule can branch on it — e.g. tell a true GET from an empty
                // POST when the body surface is '' for both.
                return $r->method;
            case 'body':
                return (string) ($r->rawBody ?? '');
            case 'request':
            default:
                $raw = $r->path . ' ' . $r->query . ' ' . (string) ($r->rawBody ?? '');

                return $raw . ' ' . rawurldecode($raw);
        }
    }
}
