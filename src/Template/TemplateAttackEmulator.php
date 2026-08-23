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
use Funnypot\Support\PathNormalizer;
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

    /** @var array<string,true> ownership keys claimed by a rule's owns_path (path-override set) */
    private $overridePaths = [];

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
        foreach ($rules as $rule) {
            if (!isset($rule['owns_path'])) {
                continue;
            }
            foreach ((array) $rule['owns_path'] as $ownershipKey) {
                $this->overridePaths[(string) $ownershipKey] = true;
            }
        }
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
            // Position-blind: computes over reflected captures only (a hand-written integer parser,
            // never eval), so it renders identically on the facade and the port — $r/clock/store unused.
            'arith-eval' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleArithEval($config, $captures, $seed);
            },
            // Parses the request body into a bounded sub-call list and fans out one item per sub-call.
            // Needs $r->rawBody, so it degrades to its request-free fallback on the position-blind port.
            'iterate' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleIterate($config, $captures, $r, $seed);
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
     * True when a rule claims this path via owns_path — the signal Honeypot::classify() uses to let
     * the request-aware attack tier override a static exact-store entry. Keyed on the shared
     * ownership form, so a case / trailing-slash probe variant of an owned path still matches.
     */
    public function ownsPath(string $requestPath): bool
    {
        return isset($this->overridePaths[PathNormalizer::ownershipKey($requestPath)]);
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
     * Content-Type default (suppressed for a bodyless 204/304, which real frameworks serve with no
     * Content-Type), the single C8 header-splitting guard, and the app-chosen status (a behavior
     * may only override it via EmulatedContent::$status — never the header set or C8).
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

        // Status is always app-chosen: a behavior may name one via EmulatedContent::$status, else
        // the rule's own status. Never model/attacker-chosen (no open redirect via a fabricated 3xx).
        $status = $content->status ?? (int) ($rule['status'] ?? 200);

        $headers = $content->headers;
        // A bodyless status (204/304) carries no Content-Type: the real frameworks strip it when
        // preparing an empty response, so defaulting one here would itself be a tell. Every other
        // response with no authored headers keeps the plain-text default.
        if ($headers === [] && !self::statusIsBodyless($status)) {
            $headers = ['Content-Type' => 'text/plain; charset=utf-8'];
        }

        // C8: a rendered header value (e.g. a reflected redirect Location) must not carry
        // CR/LF/NUL. If it does, decline this rule (no header splitting).
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1 || preg_match('/[\r\n\x00]/', $value) === 1) {
                return null;
            }
        }

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
                // The top-level captures are visible to a case `when` via the `match.N` surface,
                // so a branch can dispatch on the ONE parsed method the rule captured rather than
                // re-scanning the whole body (which a planted secondary token could steer).
                if ($this->evalConditions($r, [$case['when']], $captures) !== null) {
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
     * The `arith-eval` behavior primitive: compute a small integer expression over reflected
     * captures and render the rule's `response` with the result bound into a capture key. The
     * computation is a hand-written integer parser (NEVER eval), the operator set is closed
     * ({add,sub,mul} — no division, so it cannot divide by zero and cannot throw), and every
     * operand is magnitude-bounded. Any grammar or bound miss returns null so renderRule falls
     * back to the rule's base response — the only-upgrade-a-404 invariant, never a 500.
     *
     * Captures-only, so it renders identically on the facade and the position-blind port.
     *
     * @param array<string,mixed>      $config   the rule's `arith-eval` config
     * @param array<int|string,string> $captures reflected capture groups from the top-level match
     */
    private function handleArithEval(array $config, array $captures, int $seed): ?EmulatedContent
    {
        $value = $this->arithCompute($config, $captures);
        if ($value === null) {
            return null;
        }
        // Pure digits (XML/HTML-inert) bound into the authored capture key, reflected via {{match.KEY}}.
        $bind = (string) (isset($config['bind']) ? $config['bind'] : 'result');
        $captures[$bind] = (string) $value;

        $response = (array) (isset($config['response']) ? $config['response'] : []);
        $status = isset($response['status']) ? (int) $response['status'] : null;

        return $this->renderResponse($response, $captures, $seed, $status);
    }

    /**
     * Compute an arith-eval result, or null on any grammar/bound miss. Two authored forms:
     *  - fixed op:  `left`/`right` (capture keys) + `op` in {add,sub,mul};
     *  - expression: `expr` (a capture key) holding "<int> <op> <int>", with `ops` naming the
     *    operators authorized for that surface.
     * Operands are parsed by a fixed anchored regex (digits only) and rejected outside ±max_operand
     * (re-clamped here to ARITH_MAX_OPERAND regardless of the authored value, defence in depth).
     *
     * @param array<string,mixed>      $config
     * @param array<int|string,string> $captures
     */
    private function arithCompute(array $config, array $captures): ?int
    {
        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND;
        if ($max < 1 || $max > self::ARITH_MAX_OPERAND) {
            $max = self::ARITH_MAX_OPERAND;
        }

        if (isset($config['expr'])) {
            $expr = (string) (isset($captures[(string) $config['expr']]) ? $captures[(string) $config['expr']] : '');
            if (preg_match('/^\s*(-?\d{1,15})\s*([+\-*])\s*(-?\d{1,15})\s*$/', $expr, $m) !== 1) {
                return null;
            }
            $op = $this->arithOpName($m[2]);
            if ($op === null || !$this->arithOpAuthorized($op, $config)) {
                return null;
            }

            return $this->arithApply($op, (int) $m[1], (int) $m[3], $max);
        }

        $op = (string) (isset($config['op']) ? $config['op'] : '');
        if ($op !== 'add' && $op !== 'sub' && $op !== 'mul') {
            return null;
        }
        $left = (string) (isset($captures[(string) ($config['left'] ?? '')]) ? $captures[(string) $config['left']] : '');
        $right = (string) (isset($captures[(string) ($config['right'] ?? '')]) ? $captures[(string) $config['right']] : '');
        if (preg_match('/^-?\d{1,15}$/', $left) !== 1 || preg_match('/^-?\d{1,15}$/', $right) !== 1) {
            return null;
        }

        return $this->arithApply($op, (int) $left, (int) $right, $max);
    }

    /** Map an operator character to its op name, or null if it is not one of the closed set. */
    private function arithOpName(string $char): ?string
    {
        if ($char === '+') {
            return 'add';
        }
        if ($char === '-') {
            return 'sub';
        }
        if ($char === '*') {
            return 'mul';
        }

        return null;
    }

    /**
     * Is $op both in the closed builtin set AND authorized by this config's `ops` list? An absent
     * `ops` means no per-surface restriction beyond the closed set.
     *
     * @param array<string,mixed> $config
     */
    private function arithOpAuthorized(string $op, array $config): bool
    {
        if ($op !== 'add' && $op !== 'sub' && $op !== 'mul') {
            return false;
        }
        if (!isset($config['ops'])) {
            return true;
        }
        foreach ((array) $config['ops'] as $allowed) {
            if ((string) $allowed === $op) {
                return true;
            }
        }

        return false;
    }

    /**
     * Apply a closed-set op to two magnitude-bounded operands. Returns null when an operand is out
     * of bounds, or when the result overflows to float (a 32-bit host) — output must stay pure
     * digits. All three ops share the is_int overflow guard: on a 32-bit build add/sub can overflow
     * ±2^31 just as mul can, and a float result would render as non-digit scientific notation.
     */
    private function arithApply(string $op, int $a, int $b, int $max): ?int
    {
        if ($a < -$max || $a > $max || $b < -$max || $b > $max) {
            return null;
        }
        if ($op === 'add') {
            $sum = $a + $b;

            return is_int($sum) ? $sum : null;
        }
        if ($op === 'sub') {
            $diff = $a - $b;

            return is_int($diff) ? $diff : null;
        }
        $product = $a * $b;
        if (!is_int($product)) {
            return null;
        }

        return $product;
    }

    /**
     * The `iterate` behavior primitive: parse the request body into a bounded list of sub-calls and
     * render one `item` per sub-call, wrapped by `wrap.open`/`wrap.close`. Used to emulate an XML-RPC
     * system.multicall fan-out: one fault entry per sub-call. Safety is structural — the number of
     * items is capped by the CODE constant MAX_ITERATE_ITEMS regardless of the authored/actual count
     * (no amplification), the surface is capped before the compiler-authored parse regex runs (no
     * ReDoS, no attacker regex), and there is ZERO egress (pure string parse + render).
     *
     * The request is present only on the facade path; the position-blind port leaves $r null, so
     * there is no body to parse and the primitive degrades to its request-free `fallback` (else the
     * rule's base response). Any parse fault likewise degrades — never a 500.
     *
     * @param array<string,mixed>      $config   the rule's `iterate` config
     * @param array<int|string,string> $captures reflected capture groups from the top-level match
     */
    private function handleIterate(array $config, array $captures, ?RequestContext $r, int $seed): ?EmulatedContent
    {
        if ($r === null) {
            return $this->iterateFallback($config, $captures, $seed);
        }
        $items = $this->iterateParse($config, (string) ($r->rawBody ?? ''));
        if ($items === null) {
            return $this->iterateFallback($config, $captures, $seed);
        }
        if ($items === []) {
            return $this->iterateEmpty($config, $captures, $seed);
        }

        // HARD cap in code: the authored max_items is already clamped at compile, but re-clamp here so
        // a hand-crafted rules artifact can never make the fan-out amplify.
        $cap = isset($config['max_items']) ? (int) $config['max_items'] : self::MAX_ITERATE_ITEMS;
        if ($cap > self::MAX_ITERATE_ITEMS) {
            $cap = self::MAX_ITERATE_ITEMS;
        }
        if ($cap < 1) {
            $cap = 1;
        }
        $items = array_slice($items, 0, $cap);

        $itemBody = (string) (isset($config['item']['body']) ? $config['item']['body'] : '');
        $body = (string) (isset($config['wrap']['open']) ? $config['wrap']['open'] : '');
        foreach ($items as $i => $item) {
            // Per-item reflection rides the existing capture surface: {{xml:match.item.method}} (the
            // bounded, XML-escaped sub-call method) and {{match.item.index}}.
            $per = $captures;
            $per['item.method'] = (string) $item['method'];
            $per['item.index'] = (string) $i;
            $body .= $this->renderer->render($itemBody, $per, $seed, $this->canary);
        }
        $body .= (string) (isset($config['wrap']['close']) ? $config['wrap']['close'] : '');

        $headers = [];
        foreach ((array) (isset($config['response']['headers']) ? $config['response']['headers'] : []) as $name => $value) {
            $headers[(string) $name] = $this->renderer->render((string) $value, $captures, $seed, $this->canary);
        }
        $status = isset($config['response']['status']) ? (int) $config['response']['status'] : null;

        return new EmulatedContent($body, $headers, $status);
    }

    /**
     * Parse the request body into a bounded sub-call list for `iterate`. The parser is a CLOSED set
     * keyed by `parse` — a compiler-authored, token-bounded regex only (never an attacker regex).
     * Returns the sub-calls (each ['method'=>string]), an empty list when none parse, or null on a
     * PCRE error (fail-safe).
     *
     * @param array<string,mixed> $config
     * @return array<int,array<string,string>>|null
     */
    private function iterateParse(array $config, string $body): ?array
    {
        $parse = (string) (isset($config['parse']) ? $config['parse'] : '');
        if ($parse === 'xmlrpc-multicall') {
            return $this->parseMulticall($body);
        }

        return null;
    }

    /**
     * Structurally count the top-level sub-calls of an XML-RPC system.multicall, mirroring how real
     * WordPress deserializes the call array and takes each element struct's `methodName` member.
     *
     * A flat body-wide count OVER-counts, because a sub-call whose params nest a struct member also
     * named `methodName` would be counted as an extra sub-call. So this is depth-aware: it tracks
     * `<struct>` nesting and counts a `methodName` member ONLY at the outermost struct depth (a
     * sub-call), never one nested inside a sub-call's params.
     *
     * The walk is a single streaming pass over compiler-authored, literal-anchored tokens with
     * bounded quantifiers (no attacker regex, no nested quantifier ⇒ linear, no ReDoS), advancing an
     * offset rather than truncating the body — so the count is byte-position-independent for N up to
     * the cap and never splits a sub-call mid-token. It stops once the hard fan-out cap is provably
     * exceeded, bounding memory; the caller's array_slice is the amplification bound for N > cap.
     *
     * @return array<int,array<string,string>>|null null on a PCRE error (fail-safe)
     */
    private function parseMulticall(string $body): ?array
    {
        // Three literal-anchored tokens in one pass: a struct open, a struct close, and a
        // `<name>methodName</name>` member (capturing the wrapped method with the same bounded class
        // the top-level xmlrpc rule uses). The three are distinguished by the char after '<'.
        $token = '~(<struct\b[^>]*>)|(</struct\s*>)|<name>\s*methodName\s*</name>\s*<value>\s*(?:<string>\s*)?([\w.]{0,64})~';
        $items = [];
        $depth = 0;
        $offset = 0;
        $len = strlen($body);
        // One past the cap: enough to know N exceeds it (caller slices back to the cap), never more.
        $stop = self::MAX_ITERATE_ITEMS + 1;
        while ($offset < $len) {
            $ok = preg_match($token, $body, $m, PREG_OFFSET_CAPTURE, $offset);
            if ($ok === false || preg_last_error() !== PREG_NO_ERROR) {
                return null;
            }
            if ($ok !== 1) {
                break;
            }
            $whole = (string) $m[0][0];
            $offset = $m[0][1] + max(1, strlen($whole));
            $kind = isset($whole[1]) ? $whole[1] : '';
            if ($kind === 's') { // <struct ...>
                $depth++;
            } elseif ($kind === '/') { // </struct>
                if ($depth > 0) {
                    $depth--;
                }
            } elseif ($depth === 1) { // a methodName member at the call-array's top level
                $items[] = ['method' => (string) ($m[3][0] ?? '')];
                if (count($items) >= $stop) {
                    break;
                }
            }
        }

        return $items;
    }

    /**
     * The request-free fallback for `iterate` (port path or a parse fault): the authored
     * `fallback.response`, else null so renderRule serves the rule's base response.
     *
     * @param array<string,mixed>      $config
     * @param array<int|string,string> $captures
     */
    private function iterateFallback(array $config, array $captures, int $seed): ?EmulatedContent
    {
        if (isset($config['fallback']['response'])) {
            return $this->renderCaseResponse((array) $config['fallback']['response'], $captures, $seed);
        }

        return null;
    }

    /**
     * The zero-sub-calls response for `iterate`: the authored `empty.response`, else null so
     * renderRule serves the rule's base response.
     *
     * @param array<string,mixed>      $config
     * @param array<int|string,string> $captures
     */
    private function iterateEmpty(array $config, array $captures, int $seed): ?EmulatedContent
    {
        if (isset($config['empty']['response'])) {
            return $this->renderCaseResponse((array) $config['empty']['response'], $captures, $seed);
        }

        return null;
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

    /** 204 No Content and 304 Not Modified carry no message body and no Content-Type header. */
    private static function statusIsBodyless(int $status): bool
    {
        return $status === 204 || $status === 304;
    }

    /** Attacker-controlled surfaces are capped before regex to bound catastrophic backtracking. */
    private const MAX_SURFACE = 32768;

    /** Upper bound on segments the traversal-read canonicalizer walks — bounds the resolve loop. */
    private const MAX_TRAVERSAL_SEGMENTS = 4096;

    /** Hard ceiling on an arith-eval operand's magnitude; the authored max_operand cannot exceed it. */
    private const ARITH_MAX_OPERAND = 2147483647;

    /** Hard ceiling on iterate fan-out items, enforced regardless of the authored count — no amplification. */
    private const MAX_ITERATE_ITEMS = 64;

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
     * @param array<int|string,string>       $priorCaptures groups from the top-level match, exposed to a
     *                                        condition via the `match.N` surface (empty for the top-level match)
     * @return array<int|string,string>|null
     */
    private function evalConditions(RequestContext $r, array $conds, array $priorCaptures = []): ?array
    {
        $captures = null;
        foreach ($conds as $cond) {
            $surface = $this->surface($r, (string) ($cond['in'] ?? 'request'), $priorCaptures);
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

    /**
     * @param array<int|string,string> $priorCaptures groups from the top-level match, for the `match.N` surface
     */
    private function surface(RequestContext $r, string $in, array $priorCaptures = []): string
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

        // `match.N` / `match.NAME` — a top-level capture group, so a branch case can dispatch on the
        // ONE method the rule parsed instead of re-scanning the body. Empty for the top-level match
        // (no prior captures) and for an absent group.
        if (strncmp($in, 'match.', 6) === 0) {
            $ref = substr($in, 6);
            $key = is_numeric($ref) ? (int) $ref : $ref;

            return (string) ($priorCaptures[$key] ?? '');
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
