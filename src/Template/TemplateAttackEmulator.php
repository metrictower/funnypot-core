<?php

declare(strict_types=1);

namespace Funnypot\Core\Template;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\Behavior\NullEphemeralStore;
use Funnypot\Core\Behavior\SystemClock;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Contracts\Clock;
use Funnypot\Core\Contracts\EphemeralStore;
use Funnypot\Core\Detection;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\EmulatedContent;
use Funnypot\Core\Rules\RulesLocator;
use Funnypot\Core\Support\Chrome\Esc;
use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\Fake\FakeRecords;
use Funnypot\Core\Support\PathNormalizer;
use Funnypot\Core\Support\SafeArithmetic;
use Funnypot\Core\Support\VisualPersona;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\TemplateMatch;

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

    /** @var int|null per-deploy identity seed, for behaviors that need cross-tier coherence (e.g. decoy-session's FakeRecords) */
    private $personaSeed;

    /** @var string|null signing key for the decoy-session behavior; null/'' ⇒ that behavior is disabled */
    private $decoySessionKey;

    /** @var FingerprintGuard|null runtime fingerprint-safety gate, loaded lazily once; scans the authed
     *  decoy body before it is served so a fabricated cell can never leak an upstream detector signature */
    private $fingerprintGuard;

    /** @var bool whether the guard load has been attempted — a null guard after this is set means the
     *  denylist was unavailable, handled fail-closed (never retried per request). */
    private $fingerprintGuardLoaded = false;

    /** The mock tables the authed phpMyAdmin decoy lists in its left tree, in display order. */
    private const DECOY_TABLE_NAMES = ['users', 'password_resets', 'api_keys', 'sessions', 'orders'];

    /**
     * Column headers per mock table, matching FakeRecords' documented row shapes. Doubles as the
     * whitelist of browsable tables: a `?table=` value is honored only if it is a key here.
     *
     * @var array<string,list<string>>
     */
    private const DECOY_TABLE_COLUMNS = [
        'users' => ['id', 'username', 'email', 'created_at'],
        'password_resets' => ['email', 'reset_token', 'requested_at', 'expires_at'],
        'api_keys' => ['id', 'owner_name', 'api_key', 'created_at', 'last_used_at'],
        'sessions' => ['id', 'username', 'ip', 'last_activity'],
        'orders' => ['order_id', 'customer', 'amount', 'status', 'created_at'],
    ];

    /**
     * Named behavior primitives, keyed by the rule's `behavior` value. Each is a closure over
     * $this that turns a behavior config + captures into an EmulatedContent (or null to fall back
     * to the rule's base response). `default` is not a name here — an absent/unknown behavior is
     * simply the plain render. `branch`, `traversal-read`, `arith-eval`, `expr-eval`, `iterate`,
     * and `decoy-session` exist; other primitives are deferred.
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
        array $paramBuckets = [],
        ?int $personaSeed = null,
        ?string $decoySessionKey = null,
        bool $volatileProof = false
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
        $this->renderer = new DirectiveRenderer($personaSeed, $volatileProof);
        $this->clock = $clock ?? new SystemClock();
        $this->store = $store ?? new NullEphemeralStore();
        $this->personaSeed = $personaSeed;
        $this->decoySessionKey = $decoySessionKey;
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
            // Position-blind SSTI decoy: evaluates a full arithmetic expression from a reflected
            // capture via Support\SafeArithmetic (recursive descent, never eval), so it renders
            // identically on the facade and the port — $r/clock/store unused.
            'expr-eval' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleExprEval($config, $captures, $seed);
            },
            // Position-blind multi-fence SSTI decoy (tplmap-class confirmation): walks the reflected
            // `surface` capture as a run of engine template fences, evaluates each fence's inner
            // ARITHMETIC via Support\SafeArithmetic (recursive descent, never eval) and concatenates
            // the computed integers + fixed transforms. Reads only captures ($r/clock/store unused),
            // so it renders identically on the facade and the port.
            'ssti-render' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleSstiRender($config, $captures, $seed);
            },
            // Parses the request body into a bounded sub-call list and fans out one item per sub-call.
            // Needs $r->rawBody, so it degrades to its request-free fallback on the position-blind port.
            'iterate' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleIterate($config, $captures, $r, $seed);
            },
            // Mock-auth mint/gate over a signed decoy session cookie. Needs $r for the gate's Cookie
            // header (absent ⇒ fail closed); clock/store are unused. See handleDecoySession's docblock
            // for the full invariant list (fail-closed key check, no open redirect, etc).
            'decoy-session' => function (array $config, array $captures, ?RequestContext $r, int $seed, Clock $clock, EphemeralStore $store): ?EmulatedContent {
                return $this->handleDecoySession($config, $captures, $r, $seed);
            },
        ];
    }

    /** @param array<string,string> $canary */
    public static function fromFile(string $path, array $canary = [], ?int $personaSeed = null, ?string $decoySessionKey = null, bool $volatileProof = false): self
    {
        $rules = is_file($path) ? require $path : [];

        return new self(is_array($rules) ? $rules : [], $canary, null, null, self::loadParamBuckets(), $personaSeed, $decoySessionKey, $volatileProof);
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
    public static function fromPackage(array $canary = [], ?int $personaSeed = null, ?string $decoySessionKey = null, bool $volatileProof = false): self
    {
        return self::fromFile(RulesLocator::resolve('funnypot-attack.php'), $canary, $personaSeed, $decoySessionKey, $volatileProof);
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
     * The `expr-eval` behavior primitive: the SSTI decoy. Evaluate a full arithmetic expression
     * held in a reflected capture and render the rule's `response` with the integer result bound
     * into a capture key. The computation is Support\SafeArithmetic — a hand-written recursive-
     * descent parser (NEVER eval / a template engine / a callback): the expression is whitelisted
     * to digits + - * / % ( ) and spaces, length-capped, integer-only, and every unsafe case
     * (division/modulo by zero, overflow, an oversized or non-arithmetic payload) returns null so
     * renderRule falls back to the rule's base response — the only-upgrade invariant, never a 500.
     *
     * Only the safe integer is bound (never the raw capture), so this rule emits no attacker bytes
     * and needs no isolated origin. Captures-only, so it renders identically on the facade and the
     * position-blind port.
     *
     * @param array<string,mixed>      $config   the rule's `expr-eval` config
     * @param array<int|string,string> $captures reflected capture groups from the top-level match
     */
    private function handleExprEval(array $config, array $captures, int $seed): ?EmulatedContent
    {
        $exprKey = (string) (isset($config['expr']) ? $config['expr'] : '');
        $expr = (string) (isset($captures[$exprKey]) ? $captures[$exprKey] : '');
        if ($expr === '') {
            return null;
        }
        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND;
        $maxLen = isset($config['max_len']) ? (int) $config['max_len'] : 32;

        $value = SafeArithmetic::evaluate($expr, $max, $maxLen);
        if ($value === null) {
            return null;
        }
        // Pure digits (HTML/XML-inert) bound into the authored capture key, reflected via {{match.KEY}}.
        $bind = (string) (isset($config['bind']) ? $config['bind'] : 'result');
        $captures[$bind] = (string) $value;

        $response = (array) (isset($config['response']) ? $config['response'] : []);
        $status = isset($response['status']) ? (int) $response['status'] : null;

        return $this->renderResponse($response, $captures, $seed, $status);
    }

    /** Hard cap on the fence count in one ssti-render surface — no amplification. */
    private const SSTI_MAX_FENCES = 64;

    /** Hard cap on the ssti-render surface length; mirrors the compiler's EXPR_MAX_LEN ceiling. */
    private const SSTI_MAX_LEN = 256;

    /**
     * Hard cap on a bare-integer echo (digits). tplmap's header/trailer randoms are 10 digits; 32
     * leaves generous headroom while keeping a fence's echoed digit run bounded. A longer run
     * declines (falls through to SafeArithmetic, which then rejects it as past int32).
     */
    private const SSTI_MAX_DIGITS = 32;

    /**
     * Code-authored fence-delimiter recognisers (a CLOSED table, never built from attacker input).
     * Each row is [anchored regex with ONE inner capture, engines that enable it]. Ordered so a more
     * specific open delimiter (`${{`) is tried before a prefix of it (`${`). The inner capture is a
     * bounded tempered class ([ \t]-safe, no CR/LF, ≤254 bytes) — ReDoS-safe and never widened by any
     * attacker byte; the captured inner is only ever validated by SafeArithmetic / the fixed shape
     * regexes below, never evaluated or reflected raw.
     */
    private const SSTI_FENCES = [
        ['~\G\$\{\{((?:(?!\}\})[^\r\n]){0,254})\}\}~', ['freemarker']],
        ['~\G\{\{((?:(?!\}\})[^\r\n]){0,254})\}\}~', ['jinja2', 'twig']],
        ['~\G\$\{((?:(?!\})[^\r\n]){0,254})\}~', ['freemarker', 'javascript', 'mako']],
        ['~\G<%=((?:(?!%>)[^\r\n]){0,254})%>~', ['erb', 'javascript']],
        ['~\G#\{((?:(?!\})[^\r\n]){0,254})\}~', ['erb']],
    ];

    /**
     * The `ssti-render` behavior primitive: the multi-fence SSTI decoy for tplmap-class confirmation.
     *
     * tplmap does not send a lone `{{7*7}}`; it injects a fence RUN (`{{r1}}payload{{r2}}`) and
     * confirms only if the engine stripped the delimiters around r1/r2 AND rendered the payload,
     * using engine-specific render shapes (`|nl2br`, `print()`, `typeof(x)+y`). This handler walks the
     * reflected `surface` capture left→right; every segment must be either an enabled engine's fence
     * or a `[ \t]` gap, else the walk FAILS CLOSED (returns null → renderRule serves the inert base
     * page — never a 500, never a reflection). Each fence's inner is reduced to a rendered digit run:
     * a BARE INTEGER is echoed verbatim (strictly `[0-9]`-only, length-capped — this is how tplmap's
     * 10-digit header/trailer randoms render, which SafeArithmetic's int32 operand cap would reject);
     * anything with an operator goes through Support\SafeArithmetic::evaluate() (byte-whitelisted to
     * digits + - * / % ( ) space tab, integer-only, length/overflow-capped) — NEVER eval / a template
     * engine / a callback. The fence and shape recognisers are CODE-authored regexes over a closed
     * engine enum, so no attacker byte ever becomes a regex or an eval input, and both reduction paths
     * admit ONLY digits, so no non-digit byte can ever reach the output.
     *
     * Output is ALWAYS pure digits (+ the fixed word `number` from the JS `typeof` shape + preserved
     * `[ \t]` gaps): the concatenated per-fence renders are bound into `$config['bind']` and reflected
     * via `{{match.<bind>}}` — the raw `surface` is NEVER reflected. Any out-of-grammar payload
     * (`{{config.items()}}`, `{{''.__class__}}`, `${T(java.lang.Runtime)}`, a `<script>` between
     * fences) → some fence/byte fails → whole render declines → inert base page. So the rule emits no
     * attacker bytes, is not a live XSS even inline, and (like the sibling 45) needs no isolated origin.
     *
     * @param array<string,mixed>      $config   the rule's `ssti-render` config
     * @param array<int|string,string> $captures reflected capture groups from the top-level match
     */
    private function handleSstiRender(array $config, array $captures, int $seed): ?EmulatedContent
    {
        $surfaceKey = (string) (isset($config['surface']) ? $config['surface'] : '');
        $surface = (string) (isset($captures[$surfaceKey]) ? $captures[$surfaceKey] : '');

        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND;
        $maxLen = isset($config['max_len']) ? (int) $config['max_len'] : self::SSTI_MAX_LEN;
        if ($maxLen < 1 || $maxLen > self::SSTI_MAX_LEN) {
            $maxLen = self::SSTI_MAX_LEN;
        }
        // The surface holds the whole fence run; anything over the length cap declines outright.
        if ($surface === '' || strlen($surface) > $maxLen) {
            return null;
        }

        // Enabled engines drive BOTH the fence-delimiter set and the inner-shape transforms — a
        // closed enum, code-authored, never derived from a capture. The compiler always supplies a
        // non-empty `engines` (it defaults to the full set), so the fallback below is a defensive
        // no-op for a hand-built rule / a legacy compiled artifact.
        $engines = [];
        foreach ((array) (isset($config['engines']) ? $config['engines'] : []) as $e) {
            $engines[(string) $e] = true;
        }
        if ($engines === []) {
            foreach (self::SSTI_ENGINES_ALL as $e) {
                $engines[$e] = true;
            }
        }
        $fences = [];
        foreach (self::SSTI_FENCES as $row) {
            foreach ($row[1] as $engine) {
                if (isset($engines[$engine])) {
                    $fences[] = $row[0];
                    break;
                }
            }
        }
        $shapes = [
            'typeof' => isset($engines['javascript']),
            'print' => isset($engines['mako']),
            'nl2br' => isset($engines['twig']),
            // FreeMarker's `?c` (computer-format) builtin — tplmap's FreeMarker header is `${<rand>?c}`.
            'qc' => isset($engines['freemarker']),
        ];

        $pieces = [];
        $fenceCount = 0;
        $pos = 0;
        $len = strlen($surface);
        while ($pos < $len) {
            $ch = $surface[$pos];
            // Inter-fence gap: only space/tab (no CR/LF) — preserved verbatim in the render.
            if ($ch === ' ' || $ch === "\t") {
                $pieces[] = $ch;
                $pos++;
                continue;
            }
            $matched = false;
            foreach ($fences as $fenceRe) {
                if (preg_match($fenceRe, $surface, $m, PREG_OFFSET_CAPTURE, $pos) === 1 && $m[0][1] === $pos) {
                    $rendered = $this->sstiRenderInner($m[1][0], $shapes, $max, $maxLen);
                    if ($rendered === null) {
                        return null; // a fence whose inner is not renderable → decline the whole run
                    }
                    $pieces[] = $rendered;
                    $fenceCount++;
                    if ($fenceCount > self::SSTI_MAX_FENCES) {
                        return null;
                    }
                    $pos += strlen($m[0][0]);
                    $matched = true;
                    break;
                }
            }
            // Fail closed: any byte that is neither a recognised fence nor a [ \t] gap declines,
            // so no raw attacker byte can ever pass through to the render.
            if (!$matched) {
                return null;
            }
        }

        // tplmap shape: require ≥2 fences so a lone {{7*7}} falls through to the single-fence rules.
        if ($fenceCount < 2) {
            return null;
        }

        $bind = (string) (isset($config['bind']) ? $config['bind'] : 'rendered');
        $captures[$bind] = implode('', $pieces);

        $response = (array) (isset($config['response']) ? $config['response'] : []);
        $status = isset($response['status']) ? (int) $response['status'] : null;

        return $this->renderResponse($response, $captures, $seed, $status);
    }

    /** The closed engine enum, mirrored from the compiler; drives the fence + shape selection. */
    private const SSTI_ENGINES_ALL = ['jinja2', 'twig', 'freemarker', 'erb', 'javascript', 'mako'];

    /**
     * Reduce one fence's inner to its rendered string, or null if it is not a recognised shape.
     * Every branch ends in sstiEvalArith() — either a strict bare-integer echo or a SafeArithmetic
     * evaluation — so the output is always pure digits (the JS `typeof` shape prepends the CONSTANT
     * word `number`, which is code-authored, never an attacker byte). The shape regexes are fixed and
     * code-authored; no attacker byte becomes a regex.
     *
     * @param array<string,bool> $shapes which inner transforms are enabled (per the engine enum)
     */
    private function sstiRenderInner(string $inner, array $shapes, int $max, int $maxLen): ?string
    {
        // JS `typeof(<int>)+<int>` → invariant literal `number` + str(int2). Both integers are
        // digit-validated (typeof's arg is discarded to the constant `number`); the trailer echoes.
        if ($shapes['typeof'] && preg_match('~^[ \t]*typeof\(([0-9 \t]{1,32})\)[ \t]*\+[ \t]*([0-9 \t]{1,32})[ \t]*$~', $inner, $m) === 1) {
            $a = $this->sstiEvalArith($m[1], $max, $maxLen);
            $b = $this->sstiEvalArith($m[2], $max, $maxLen);
            if ($a === null || $b === null) {
                return null;
            }

            return 'number' . $b;
        }
        // FreeMarker `${<digits>?c}` computer-format builtin → echo the (digit-only) argument.
        if ($shapes['qc'] && preg_match('~^[ \t]*([0-9]{1,' . self::SSTI_MAX_DIGITS . '})[ \t]*\?c[ \t]*$~', $inner, $m) === 1) {
            return $m[1];
        }
        // Mako `print(<arith>)` → unwrap to the arithmetic argument, then reduce.
        if ($shapes['print'] && preg_match('~^[ \t]*print\(([0-9+\-*/%() \t]{1,64})\)[ \t]*$~', $inner, $m) === 1) {
            return $this->sstiEvalArith($m[1], $max, $maxLen);
        }
        // Twig `<arith>|nl2br` → strip the filter, then reduce the arithmetic prefix.
        if ($shapes['nl2br'] && preg_match('~^([0-9+\-*/%() \t]{1,64})\|nl2br[ \t]*$~', $inner, $m) === 1) {
            return $this->sstiEvalArith($m[1], $max, $maxLen);
        }
        // Bare integer (tplmap's random header/trailer) or bare arithmetic (all engines).
        return $this->sstiEvalArith($inner, $max, $maxLen);
    }

    /**
     * Reduce one arithmetic fragment to its rendered digit string, or null.
     *
     * A BARE INTEGER (optionally `[ \t]`-padded) is echoed VERBATIM — strictly `[0-9]`-only and
     * length-capped to SSTI_MAX_DIGITS. This is the ONLY path that reflects an attacker-supplied
     * number (inherent to tplmap confirmation, whose 10-digit header/trailer randoms exceed
     * SafeArithmetic's int32 operand cap and so cannot flow through the evaluator). The `^[0-9]+$`
     * gate admits no other byte, so the echo is provably digit-only — no markup, CRLF, or injection
     * can transit it. Anything containing an operator/paren goes to SafeArithmetic (int32-bounded,
     * integer-only), whose output is likewise pure computed digits. A run longer than the digit cap
     * falls through to SafeArithmetic and is rejected there (past int32) → null → decline.
     */
    private function sstiEvalArith(string $expr, int $max, int $maxLen): ?string
    {
        if (preg_match('~^[ \t]*([0-9]{1,' . self::SSTI_MAX_DIGITS . '})[ \t]*$~', $expr, $m) === 1) {
            return $m[1];
        }
        $v = SafeArithmetic::evaluate($expr, $max, $maxLen);
        // Decline a NEGATIVE result too: stringifying it would emit a '-', breaking the
        // digit-only output invariant this decoy's safety rests on (FP-0234 re-review N1). Inert
        // regardless (a hyphen cannot inject), and tplmap never sends negative-producing arithmetic,
        // so efficacy is unaffected — a negative fence simply declines to the inert base page.
        return ($v === null || $v < 0) ? null : (string) $v;
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
     * The `decoy-session` behavior primitive: a stateless mock-auth mint/gate over a signed
     * DecoySession cookie. Two config-driven modes on the same primitive:
     *  - `mint` (the login POST): a plausible, non-empty username/password mints the session
     *    cookie and redirects to the authed panel — but the redirect target is a FIXED literal,
     *    never the submitted value (no open redirect), and an empty/whitespace credential is
     *    declined so a blank submit is not treated as a login.
     *  - `gate` (the authed panel GET): only a verified `s=1` cookie renders the authed body;
     *    anything else (absent, garbage, a validly-signed but wrong-class `s=0`, or no request at
     *    all) declines to null so renderRule falls back to the rule's base `response` — the
     *    login page. This is fail-closed by construction: the ONLY path to the authed body is
     *    DecoySession::isAuthenticated() returning true.
     *
     * The signing key is checked FIRST and is a hard kill switch: null/'' declines before a
     * DecoySession/Honeytoken is ever constructed (DecoySession's ctor takes a non-nullable
     * string under strict_types, so passing null would TypeError -> 500, not decline). The key
     * itself is never rendered, reflected, or logged — it exists only to construct DecoySession.
     *
     * @param array<string,mixed>      $config   the rule's `decoy-session` config (`mode` + cookie/table naming)
     * @param array<int|string,string> $captures reflected capture groups (mint reads `user`/`pass`)
     */
    private function handleDecoySession(array $config, array $captures, ?RequestContext $r, int $seed): ?EmulatedContent
    {
        if ($this->decoySessionKey === null || $this->decoySessionKey === '') {
            return null;
        }

        $mode = (string) ($config['mode'] ?? '');
        $name = (string) ($config['cookie_name'] ?? 'phpMyAdmin');
        $path = (string) ($config['cookie_path'] ?? '/');
        $session = new DecoySession($this->decoySessionKey);

        if ($mode === 'mint') {
            return $this->decoySessionMint($session, $config, $captures, $name, $path);
        }
        if ($mode === 'gate') {
            return $this->decoySessionGate($session, $config, $r, $name, $seed);
        }

        return null;
    }

    /**
     * The mint half: an empty/whitespace-only username or password is not a login attempt, so it
     * declines (-> the base login-page response), as does an implausible username. Otherwise mint
     * the `s=1` cookie and redirect. The Location is a FIXED literal — captures are read ONLY for
     * the credential check, never woven into a header, so a crafted redirect/servername field in
     * the POST body can never steer the client anywhere (no open redirect).
     *
     * @param array<string,mixed>      $config
     * @param array<int|string,string> $captures
     */
    private function decoySessionMint(DecoySession $session, array $config, array $captures, string $name, string $path): ?EmulatedContent
    {
        $user = (string) ($captures['user'] ?? '');
        $pass = (string) ($captures['pass'] ?? '');
        if (trim($user) === '' || trim($pass) === '') {
            return null;
        }
        if (preg_match('/^[A-Za-z0-9_.@-]{1,64}$/', $user) !== 1) {
            return null;
        }

        $cookie = $session->mintCookie($name, $path);

        return new EmulatedContent('', ['Set-Cookie' => $cookie, 'Location' => '/phpmyadmin/index.php'], 302);
    }

    /**
     * The gate half: fails closed on anything but a verified `s=1` cookie (isAuthenticated() is
     * the ONLY authentication path). The Cookie header is read case-insensitively, mirroring
     * surface()'s strcasecmp loop — a null $r (the position-blind port) has no cookie to read, so
     * it degrades to the same fail-closed decline.
     *
     * @param array<string,mixed> $config
     */
    private function decoySessionGate(DecoySession $session, array $config, ?RequestContext $r, string $name, int $seed): ?EmulatedContent
    {
        // Canonical trailing-slash redirect (what Apache DirectorySlash does in front of real
        // phpMyAdmin): a bare directory request like `/phpmyadmin` 301s to `/phpmyadmin/` so the login
        // page loads under a trailing-slash base and its relative form `action="index.php?route=/"`
        // resolves to the owned `/phpmyadmin/index.php` rather than escaping to a bare `/index.php`
        // (which this decoy does not own, so it would fall through to an unrelated rule). Opt-in per
        // rule; fires before the auth check so it applies with or without a cookie.
        if ($r !== null && !empty($config['canonical_slash'])) {
            $redirect = $this->canonicalSlashRedirect($r->path);
            if ($redirect !== null) {
                return $redirect;
            }
        }

        $cookieHeader = null;
        if ($r !== null) {
            foreach ($r->headers as $key => $value) {
                if (strcasecmp((string) $key, 'Cookie') === 0) {
                    $cookieHeader = (string) $value;
                    break;
                }
            }
        }
        if (!$session->isAuthenticated($cookieHeader, $name)) {
            return null;
        }

        return $this->decoySessionAuthedBody($config, $seed, $r);
    }

    /**
     * A 301 to `$path.'/'` when $path is a bare directory (no trailing slash, and its last segment has
     * no dot so it is not a file like `…/index.php`), else null. The Location is $path with a single
     * appended slash: $path already passed the rule's own path regex, so it is one of the owned panel
     * aliases — appending '/' keeps it same-origin and same-path (no open redirect, no reflected
     * arbitrary target). Mirrors an Apache DirectorySlash 301 (status + Content-Type + body shape).
     */
    private function canonicalSlashRedirect(string $path): ?EmulatedContent
    {
        if ($path === '' || substr($path, -1) === '/') {
            return null;
        }
        $slash = strrpos($path, '/');
        $segment = $slash === false ? $path : substr($path, $slash + 1);
        if (strpos($segment, '.') !== false) {
            return null;
        }

        $target = $path . '/';
        $href = htmlspecialchars($target, ENT_QUOTES, 'UTF-8');
        $body = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
            . "<html><head>\n<title>301 Moved Permanently</title>\n</head><body>\n"
            . "<h1>Moved Permanently</h1>\n"
            . "<p>The document has moved <a href=\"{$href}\">here</a>.</p>\n"
            . "</body></html>\n";

        return new EmulatedContent(
            $body,
            ['Content-Type' => 'text/html; charset=iso-8859-1', 'Location' => $target],
            301
        );
    }

    /**
     * The authed decoy body: a hand-authored phpMyAdmin browse screen showing a fabricated "breached
     * database" — the left tree lists the mock tables (DECOY_TABLE_NAMES) and the grid shows the
     * selected one's rows, all seeded from FakeRecords. Renders through the shared core PhpMyAdminSkin
     * so this tier and any template tier show ONE coherent product identity (class prefix + MySQL
     * version banner are both seed-derived by the skin, never a fleet-wide literal).
     *
     * The rendered body is scanned by the runtime FingerprintGuard BEFORE it is served: a fabricated
     * cell that happened to spell an upstream detector's signature (a bare CRS rule id, a matcher word)
     * would let an attacker classify the reply as canned. Any hit — or a guard that could not load —
     * fails CLOSED (return null → the gate declines → the base login page renders): never serve an
     * unverified body, and never throw (a 500 is itself a tell), so this returns null rather than
     * raising. The local guard-load try/catch is that fail-closed conversion, not error-swallowing.
     *
     * The deploy seed prefers $this->personaSeed (per-deploy coherence across the persona/template
     * tiers) and falls back to the per-render $seed. Row count is re-clamped to MAX_DECOY_ROWS
     * regardless of the authored value (mirrors handleIterate's fan-out cap) — no amplification via a
     * hand-crafted rules artifact.
     *
     * @param array<string,mixed> $config
     */
    private function decoySessionAuthedBody(array $config, int $seed, ?RequestContext $r): ?EmulatedContent
    {
        $deploySeed = $this->personaSeed ?? $seed;
        $persona = VisualPersona::fromSeed($deploySeed);
        // The fake rows' email/account host tracks the SAME persona the skin renders (topbar server, db
        // slug, MySQL version), so a fabricated user never disagrees with the site identity around it. An
        // authored `domain` still wins — typically the `{{persona.company.domain}}` directive, which a
        // plain literal round-trips through render() unchanged (DirectiveRenderer's fast path). The
        // fallback is the coherent persona domain: the compiler normalizes an OMITTED `domain` to '', and
        // an empty host would render bare `user@` cells, so an empty render resolves to the persona domain
        // rather than a giveaway literal like `example.com`.
        $authoredDomain = (string) ($config['domain'] ?? '');
        $rendered = $authoredDomain !== '' ? $this->renderer->render($authoredDomain, [], $seed, $this->canary) : '';
        $domain = $rendered !== '' ? $rendered : $persona->domain();
        $panelKey = (string) ($config['table_key'] ?? 'users');

        $rows = isset($config['rows']) ? (int) $config['rows'] : 10;
        if ($rows < 0) {
            $rows = 0;
        }
        $rows = min($rows, self::MAX_DECOY_ROWS);

        $table = $this->decoySessionSelectedTable($r);
        $slots = PageSlots::trusted(
            'phpMyAdmin',
            '',
            $table,
            '',
            self::DECOY_TABLE_NAMES,
            self::DECOY_TABLE_COLUMNS[$table],
            $this->decoySessionTableRows($table, $deploySeed, $domain, $panelKey, $rows),
            [],
            '',
            ''
        );

        $displayPath = $r !== null ? $r->path : '/phpmyadmin/index.php';
        $html = (new PhpMyAdminSkin())->render(
            $slots,
            $persona,
            Esc::text($displayPath),
            $displayPath
        );

        // Verify-before-serve: a fabricated body carrying an upstream-detector signature, or a guard we
        // could not load, fails closed to the login page rather than serving it or 500-ing.
        $guard = $this->fingerprintGuard();
        if ($guard === null || $guard->scan($html) !== []) {
            return null;
        }

        return new EmulatedContent($html, ['Content-Type' => 'text/html; charset=utf-8'], 200);
    }

    /**
     * Pick which mock table to browse from the request's `?table=` query, whitelisted against
     * DECOY_TABLE_COLUMNS. The raw query value is only ever compared to the whitelist keys, never
     * reflected, so a crafted value can neither inject nor steer output; an absent/unknown/position-
     * blind ($r === null) request shows `users`.
     */
    private function decoySessionSelectedTable(?RequestContext $r): string
    {
        if ($r === null || $r->query === '') {
            return 'users';
        }
        $params = [];
        parse_str($r->query, $params);
        $requested = isset($params['table']) && is_string($params['table']) ? $params['table'] : '';

        return isset(self::DECOY_TABLE_COLUMNS[$requested]) ? $requested : 'users';
    }

    /**
     * The seeded rows for one mock table. apiKeys and orders take no domain (no cell shows one); the
     * rest fold the persona domain into the row draw so emails/accounts agree with the site identity.
     *
     * @return list<list<string>>
     */
    private function decoySessionTableRows(string $table, int $seed, string $domain, string $key, int $n): array
    {
        switch ($table) {
            case 'password_resets':
                return FakeRecords::passwordResets($seed, $domain, $key, $n);
            case 'api_keys':
                return FakeRecords::apiKeys($seed, $key, $n);
            case 'sessions':
                return FakeRecords::sessions($seed, $domain, $key, $n);
            case 'orders':
                return FakeRecords::orders($seed, $key, $n);
            case 'users':
            default:
                return FakeRecords::users($seed, $domain, $key, $n);
        }
    }

    /**
     * The runtime fingerprint-safety gate, lazily loaded once from the package denylist. Returns null
     * if the artifact can't be loaded — the caller treats that as "cannot verify" and fails closed.
     * The load failure is cached (fingerprintGuardLoaded) so it isn't retried on every request, and the
     * try/catch keeps a missing/broken denylist from escaping as a 500 on the hot path.
     */
    private function fingerprintGuard(): ?FingerprintGuard
    {
        if (!$this->fingerprintGuardLoaded) {
            $this->fingerprintGuardLoaded = true;
            try {
                $this->fingerprintGuard = FingerprintGuard::fromPackage();
            } catch (\Throwable $e) {
                $this->fingerprintGuard = null;
            }
        }

        return $this->fingerprintGuard;
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

    /** Hard ceiling on decoy-session gate table rows, enforced regardless of the authored count. */
    private const MAX_DECOY_ROWS = 100;

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
                // A second decode pass recovers double-encoded WAF-evasion payloads (%253b -> %3b
                // -> ;), added only when an encoded octet survived the first pass. Callers cap the
                // result at MAX_SURFACE, so the extra copy cannot amplify backtracking cost.
                $once = rawurldecode($raw);
                if (preg_match('~%[0-9A-Fa-f]{2}~', $once) !== 1) {
                    return $raw . ' ' . $once;
                }

                return $raw . ' ' . $once . ' ' . rawurldecode($once);
        }
    }
}
