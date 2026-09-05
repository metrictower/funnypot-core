<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Attack\AttackBodies;
use Funnypot\Core\SchemaVersion;
use Funnypot\Core\Support\PathNormalizer;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SurfaceGraph;
use Funnypot\Core\Template\DirectiveRenderer;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Compiles funnypot attack templates (YAML) into the frozen rules array the runtime
 * TemplateAttackEmulator interprets. Build-time only (needs symfony/yaml); the emitted
 * PHP array is pure data, so the runtime stays PHP-only.
 *
 * Rule order = first-match-wins; control it with an optional `priority` (lower first),
 * then `id`. The `NN-` filename prefix is a cosmetic aid only — `priority` is the real key.
 *
 * The compile step is where "compiles but silently dead" becomes a build failure: unique
 * ids, a closed directive vocabulary, no CR/LF in static headers, and an optional `expect:`
 * marker assertion (render with empty captures, assert the scanner's marker survives).
 */
final class EmulatorCompiler
{
    /**
     * @return array<int,array<string,mixed>>
     */
    public function compile(string $dir): array
    {
        return $this->compileDirs([$dir]);
    }

    /**
     * Compile several template dirs into one first-match-wins rule set. Order across dirs
     * doesn't matter — `priority` (then `id`) is the real key — so hand-authored attack
     * templates and CRS-broadened ones can live in separate dirs and still sort correctly.
     *
     * @param string[] $dirs
     * @return array<int,array<string,mixed>>
     */
    public function compileDirs(array $dirs): array
    {
        $files = TemplateGlob::yaml($dirs);

        $rules = [];
        $seenIds = [];
        foreach ($files as $file) {
            $doc = Yaml::parseFile($file);
            if (!is_array($doc)) {
                throw new RuntimeException("Template is not a mapping: {$file}");
            }
            $rule = $this->normalize($doc, $file);

            $id = $rule['id'];
            if (isset($seenIds[$id])) {
                throw new RuntimeException("Duplicate template id '{$id}' ({$file} and {$seenIds[$id]}); ids must be unique or first-match-wins silently shadows a rule.");
            }
            $seenIds[$id] = $file;

            $rules[] = $rule;
        }

        usort($rules, static function (array $a, array $b): int {
            return $a['_priority'] <=> $b['_priority'] ?: strcmp($a['id'], $b['id']);
        });

        // Drop the sort key from the emitted rules.
        return array_map(static function (array $rule): array {
            unset($rule['_priority']);

            return $rule;
        }, $rules);
    }

    /**
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    private function normalize(array $doc, string $file): array
    {
        foreach (['id', 'match', 'response'] as $required) {
            if (!isset($doc[$required])) {
                throw new RuntimeException("Template {$file} missing '{$required}'.");
            }
        }

        $version = (int) ($doc['version'] ?? 1);
        if ($version > SchemaVersion::CURRENT) {
            throw new RuntimeException("Template {$file}: schema version {$version} exceeds the engine's supported schema " . SchemaVersion::CURRENT . " — refusing to compile (upgrade funnypot-core).");
        }

        $match = [];
        foreach ((array) $doc['match'] as $cond) {
            if (!is_array($cond)) {
                throw new RuntimeException("Template {$file}: each match condition needs 'in' + 'regex'|'contains'.");
            }
            $match[] = $this->normalizeCondition($cond, $file);
        }

        $response = (array) $doc['response'];
        $headers = array_map('strval', (array) ($response['headers'] ?? []));
        $body = (string) ($response['body'] ?? '');

        $this->assertKnownDirectives($body, $file);
        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file, true);
            $this->assertKnownDirectives($value, $file, true);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }
        $this->assertMarkers($doc, $body, $headers, $file);
        $this->assertHtmlReflectionSafe($doc, $file);

        $rule = [
            'id' => (string) $doc['id'],
            'severity' => (string) ($doc['severity'] ?? 'high'),
            'tags' => array_map('strval', (array) ($doc['tags'] ?? [])),
            'status' => $this->normalizeStatus($doc['status'] ?? 200, $file),
            'match' => $match,
            'response' => [
                'headers' => $headers,
                'body' => $body,
            ],
            '_priority' => (int) ($doc['priority'] ?? 100),
        ];

        // Reflecting-decoy marker: this rule echoes attacker request bytes into an active context
        // (an HTML body or a redirect Location). The runtime serves it only from an isolated origin
        // (Config::$isolatedOrigin); inline in a response-owning host it would be a live XSS/redirect.
        if (!empty($doc['reflects_input'])) {
            $rule['reflects_input'] = true;
        }

        // The reflection class (Config::$reflectClasses knob key). Carried alongside reflects_input
        // so the per-class serve gate (Config::serveReflector) can target this rule specifically.
        if (isset($doc['reflect_class'])) {
            $rule['reflect_class'] = (string) $doc['reflect_class'];
        }

        // Cheap literal pre-filter hint for the runtime: a substring that must be present in a
        // named surface for this rule to have any chance of matching. Only emitted when it is
        // provably required (see requiredLiteral); rules without one keep the always-evaluate
        // path. Purely a performance shortcut — never allowed to change which rule matches.
        $literal = $this->requiredLiteral($match);
        if ($literal !== null) {
            $rule['lit'] = $literal['lit'];
            $rule['lit_in'] = $literal['in'];
            $rule['lit_ci'] = $literal['ci'];
        }

        // Optional path ownership: paths this request-aware rule claims from the static exact-store.
        // Canonicalized to the ownership key so the engine's ownsPath() lookup collapses case /
        // trailing-slash probe variants. A plain path, never a signature (fingerprint-safe).
        if (isset($doc['owns_path'])) {
            $owns = [];
            $rawOwns = [];
            foreach ((array) $doc['owns_path'] as $p) {
                $p = (string) $p;
                if ($p === '' || $p[0] !== '/') {
                    throw new RuntimeException("Template {$file}: owns_path entry '{$p}' must be an absolute path.");
                }
                $rawOwns[] = $p;
                $owns[] = PathNormalizer::ownershipKey($p);
            }
            $rule['owns_path'] = array_values(array_unique($owns));

            // Variant-coverage check: ownsPath() claims a request whenever its ownershipKey (any
            // case, any count of trailing slashes) matches an owned entry. If the rule's own
            // `in: path` match is stricter than that, a claimed variant can still DECLINE the
            // rule match — a silent fallthrough (mitigated at runtime by
            // Honeypot::hasAuthSuccessWitness, but worth flagging at author time). A warning, not
            // a build failure: some owns_path rules intentionally rely on that runtime safety net
            // instead of full variant coverage.
            foreach ($this->ownsPathVariantWarnings($rawOwns, $match, $file) as $warning) {
                fwrite(STDERR, "warning: {$warning}\n");
            }
        }

        // Optional persona gate: the compiled pid a rule's owning deploy-persona must resolve to for
        // this rule to fire. Threaded explicitly because $rule is built from a whitelist (unknown
        // top-level doc keys are dropped). A plain pid string, never a signature (fingerprint-safe);
        // Honeypot::personaGateAllows() compares it to the served `/` persona pick so an owns_path
        // rule that presents a specific stack (e.g. the Next.js RSC responder) fires ONLY where that
        // stack is the deploy's actual homepage persona — never fleet-wide.
        if (isset($doc['persona_gate'])) {
            $rule['persona_gate'] = (string) $doc['persona_gate'];
        }

        // An optional named behavior primitive. The base `response` above stays the ultimate
        // fallback; the behavior only picks the content when it fires. Unknown names are a build
        // failure — this build knows branch, arith-eval, expr-eval, iterate, and decoy-session
        // (other primitives are deferred).
        if (isset($doc['behavior'])) {
            $behavior = (string) $doc['behavior'];
            switch ($behavior) {
                case 'branch':
                    $rule['behavior'] = 'branch';
                    $rule['branch'] = $this->normalizeBranch((array) ($doc['branch'] ?? []), $file);
                    break;
                case 'arith-eval':
                    $rule['behavior'] = 'arith-eval';
                    $rule['arith-eval'] = $this->normalizeArithEval((array) ($doc['arith-eval'] ?? []), $file);
                    break;
                case 'expr-eval':
                    $rule['behavior'] = 'expr-eval';
                    $rule['expr-eval'] = $this->normalizeExprEval((array) ($doc['expr-eval'] ?? []), $file);
                    break;
                case 'ssti-render':
                    $rule['behavior'] = 'ssti-render';
                    $rule['ssti-render'] = $this->normalizeSstiRender((array) ($doc['ssti-render'] ?? []), $file);
                    break;
                case 'iterate':
                    $rule['behavior'] = 'iterate';
                    $rule['iterate'] = $this->normalizeIterate((array) ($doc['iterate'] ?? []), $file);
                    break;
                case 'decoy-session':
                    $rule['behavior'] = 'decoy-session';
                    $rule['decoy-session'] = $this->normalizeDecoySession((array) ($doc['decoy-session'] ?? []), $file);
                    break;
                default:
                    throw new RuntimeException("Template {$file}: unknown behavior '{$behavior}'. This build knows 'branch', 'arith-eval', 'expr-eval', 'ssti-render', 'iterate', 'decoy-session'.");
            }
        }

        return $rule;
    }

    /**
     * Compile-time guard for the owns_path/path-match variant-coverage bug: TemplateAttackEmulator's
     * ownsPath() claims a request whenever PathNormalizer::ownershipKey(requestPath) equals a
     * declared owns_path entry — that key function lower-cases the path and strips ALL trailing
     * slashes, so ownsPath() is true for every case/trailing-slash variant of the owned path. If the
     * rule's own `in: path` match condition(s) are stricter (case-sensitive, or intolerant of a
     * doubled trailing slash), a variant request makes ownsPath() TRUE but matchRule() decline —
     * classify() then falls through past this rule entirely. Mirrors the runtime's own regex
     * construction exactly (`~regex~` + `i` iff ci, `s` iff dotall — see
     * TemplateAttackEmulator::evalConditions) so the compile-time probe matches runtime behavior.
     *
     * Returns one warning string per (owns_path entry, failing variant) — never throws: an
     * owns_path rule with a stricter path match isn't automatically unsafe (the runtime
     * Honeypot::hasAuthSuccessWitness guard is the actual backstop), so this only flags the class
     * of bug for an author to review, it doesn't fail the build.
     *
     * @param string[]                        $rawOwns the as-authored owns_path entries (before ownershipKey canonicalization)
     * @param array<int,array<string,mixed>>  $match   the rule's normalized match conditions
     * @return string[]
     */
    private function ownsPathVariantWarnings(array $rawOwns, array $match, string $file): array
    {
        $pathConditions = [];
        foreach ($match as $cond) {
            if (($cond['in'] ?? '') === 'path') {
                $pathConditions[] = $cond;
            }
        }

        $warnings = [];
        foreach ($rawOwns as $raw) {
            $canon = PathNormalizer::ownershipKey($raw);

            // The exact variant set ownsPath() collapses onto this owned path: any case, and any
            // count (0 or more) of trailing slashes. Testing the as-authored form too catches an
            // owns_path entry itself written with mixed case or a trailing slash.
            $variants = array_unique([
                $raw, $raw . '/', $raw . '//', strtoupper($raw),
                $canon, $canon . '/', $canon . '//', strtoupper($canon),
            ]);

            if ($pathConditions === []) {
                $warnings[] = "Template {$file}: owns_path '{$raw}' but the rule has no 'in: path' match condition — it can never match its owned path.";
                continue;
            }

            foreach ($pathConditions as $cond) {
                if (!isset($cond['regex'])) {
                    $warnings[] = "Template {$file}: owns_path '{$raw}' but its 'in: path' condition has no regex to verify variant coverage — an owns_path rule's path regex must be case-insensitive and tolerate trailing slashes (use `/*\$` + `ci: true`), or ownsPath will claim a request the rule declines. See the login-oracle templates.";
                    continue;
                }
                $ci = ($cond['ci'] ?? true) !== false;
                $flags = ($ci ? 'i' : '') . (($cond['dotall'] ?? false) ? 's' : '');
                foreach ($variants as $variant) {
                    $hit = @preg_match('~' . $cond['regex'] . '~' . $flags, $variant);
                    if ($hit !== 1) {
                        $warnings[] = "Template {$file}: owns_path '{$raw}' but the path match does not accept variant '{$variant}' — an owns_path rule's path regex must be case-insensitive and tolerate trailing slashes (use `/*\$` + `ci: true`), or ownsPath will claim a request the rule declines. See the login-oracle templates.";
                    }
                }
            }
        }

        return $warnings;
    }

    /**
     * Normalize one match/`when` condition into the runtime shape: `in` + `regex`|`contains`, with
     * the optional ci/dotall/capture switches carried through. Regexes are compile-checked. Shared
     * by the top-level rule match and a branch case's `when`.
     *
     * @param array<string,mixed> $cond
     * @return array<string,mixed>
     */
    private function normalizeCondition(array $cond, string $file): array
    {
        if (!isset($cond['in'])) {
            throw new RuntimeException("Template {$file}: each match condition needs 'in' + 'regex'|'contains'.");
        }
        $one = ['in' => (string) $cond['in']];
        if (isset($cond['regex'])) {
            $one['regex'] = (string) $cond['regex'];
            $this->assertValidRegex($one['regex'], (bool) ($cond['dotall'] ?? false), $file);
        } elseif (isset($cond['contains'])) {
            $one['contains'] = (string) $cond['contains'];
        } else {
            throw new RuntimeException("Template {$file}: condition needs 'regex' or 'contains'.");
        }
        // Optional per-condition switches, carried through to the runtime interpreter.
        if (isset($cond['ci'])) {
            $one['ci'] = (bool) $cond['ci'];
        }
        if (!empty($cond['dotall'])) {
            $one['dotall'] = true;
        }
        if (!empty($cond['capture'])) {
            $one['capture'] = true;
        }

        return $one;
    }

    /**
     * Normalize a `branch` behavior config: a non-empty `cases` list (each a `when` condition + a
     * `response`) and an optional `default.response`. Every authored response is directive- and
     * static-header-checked exactly like a base response, so a branch case can never smuggle a
     * typo'd directive or a CR/LF-bearing static header past the build.
     *
     * @param array<string,mixed> $branch
     * @return array<string,mixed>
     */
    private function normalizeBranch(array $branch, string $file): array
    {
        $cases = [];
        foreach ((array) ($branch['cases'] ?? []) as $case) {
            if (!is_array($case)) {
                throw new RuntimeException("Template {$file}: each branch case must be a mapping with 'when' + 'response'.");
            }
            // A case MUST author a `response` (same as `default`); a typo'd `respons:` would
            // otherwise compile and a matched case would serve an empty 200.
            if (!isset($case['response'])) {
                throw new RuntimeException("Template {$file}: each branch case must author a 'response'.");
            }
            $cases[] = [
                'when' => $this->normalizeCondition((array) ($case['when'] ?? []), $file),
                'response' => $this->normalizeBehaviorResponse((array) $case['response'], $file),
            ];
        }
        if ($cases === []) {
            throw new RuntimeException("Template {$file}: behavior 'branch' needs at least one entry in 'branch.cases'.");
        }

        $out = ['cases' => $cases];

        if (isset($branch['default'])) {
            $default = (array) $branch['default'];
            if (!isset($default['response'])) {
                throw new RuntimeException("Template {$file}: branch 'default' must author a 'response'.");
            }
            $out['default'] = ['response' => $this->normalizeBehaviorResponse((array) $default['response'], $file)];
        }

        return $out;
    }

    /** The closed arith-eval operator set — validated at build so an unknown op never compiles. */
    private const ARITH_OPS = ['add', 'sub', 'mul'];

    /** Hard ceiling on an arith-eval operand's magnitude; a larger authored max_operand is clamped down. */
    private const ARITH_MAX_OPERAND = 2147483647;

    /** The default operand bound when a template authors none. */
    private const ARITH_MAX_OPERAND_DEFAULT = 1000000;

    /** The closed set of iterate body parsers — an unknown `parse` is a build failure. */
    private const ITERATE_PARSERS = ['xmlrpc-multicall'];

    /** Hard ceiling on iterate fan-out items; a larger authored max_items is clamped down. */
    private const MAX_ITERATE_ITEMS = 64;

    /** The closed decoy-session mode set: mint (the login POST) or gate (the authed GET/HEAD). */
    private const DECOY_SESSION_MODES = ['mint', 'gate'];

    /** The closed authed-panel set a gate rule may render: the phpMyAdmin breached-DB browser (default,
     *  legacy) or the WordPress admin dashboard. An unknown value is a build failure. */
    private const DECOY_SESSION_PANELS = ['phpmyadmin', 'wordpress'];

    /** The default mint redirect Location — the phpMyAdmin panel, so an artifact authored before the
     *  `redirect` key (and any hand-built legacy rule) mints byte-identically to before. */
    private const DECOY_MINT_REDIRECT_DEFAULT = '/phpmyadmin/index.php';

    /**
     * Normalize a `decoy-session` behavior config: a closed `mode` (mint|gate) plus the
     * `cookie_name`/`cookie_path` the mint/gate pair must agree on. Mint mode carries an optional
     * `redirect` (a static rooted-relative 302 Location literal, default the phpMyAdmin panel). Gate
     * mode carries a closed `panel` (which authed shell to render, default phpmyadmin) plus the
     * FakeRecords inputs the authed body needs (`domain`, `table_key`, `rows`) — the gate keys are only
     * normalized for a gate rule, and `redirect` only for a mint rule. `domain` may carry a
     * directive (e.g. `{{persona.company.domain}}`, rendered at request time by
     * TemplateAttackEmulator::decoySessionAuthedBody), so it gets the same directive-vocabulary
     * lint as a response body/header — a typo'd persona field would otherwise render '' silently.
     * No `response` here: the rule's own base `response` (the login page) is the fallback this
     * primitive declines to, so there is nothing behavior-specific to directive/static-header-check.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeDecoySession(array $config, string $file): array
    {
        $mode = (string) ($config['mode'] ?? '');
        if (!in_array($mode, self::DECOY_SESSION_MODES, true)) {
            throw new RuntimeException("Template {$file}: behavior 'decoy-session' needs a 'mode' of " . implode('|', self::DECOY_SESSION_MODES) . '.');
        }
        $cookieName = (string) ($config['cookie_name'] ?? '');
        $cookiePath = (string) ($config['cookie_path'] ?? '');
        if ($cookieName === '' || $cookiePath === '') {
            throw new RuntimeException("Template {$file}: behavior 'decoy-session' needs a non-empty 'cookie_name' and 'cookie_path'.");
        }
        // cookie_name may now carry a directive (e.g. wordpress_logged_in_{{persona.wordpress.cookieHash}})
        // so the minted cookie's NAME is per-deploy rather than a fleet-wide literal; it is rendered at
        // request time (handleDecoySession threads it through DirectiveRenderer). Directive-vocabulary
        // lint it like a response header so a typo'd persona field can't render '' silently. A plain
        // literal (the phpMyAdmin pair's `phpMyAdmin`) carries no directive and round-trips unchanged.
        $this->assertKnownDirectives($cookieName, $file, true);

        $out = [
            'mode' => $mode,
            'cookie_name' => $cookieName,
            'cookie_path' => $cookiePath,
        ];

        if ($mode === 'mint') {
            // The 302 Location the mint sends. A STATIC rooted-relative literal only — never attacker-
            // or directive-shaped (the no-open-redirect invariant): non-empty, starts with a single '/'
            // (not protocol-relative '//'), no backslash, no CR/LF/NUL, no '{{' directive. Absent ⇒ the
            // phpMyAdmin default, so the shipped pma mint and any legacy artifact are byte-identical.
            $redirect = isset($config['redirect']) ? (string) $config['redirect'] : self::DECOY_MINT_REDIRECT_DEFAULT;
            if ($redirect === ''
                || $redirect[0] !== '/'
                || strpos($redirect, '//') === 0
                || strpos($redirect, '\\') !== false
                || strpos($redirect, '{{') !== false
                || preg_match('/[\r\n\x00]/', $redirect) === 1
            ) {
                throw new RuntimeException("Template {$file}: behavior 'decoy-session' mint 'redirect' must be a static rooted-relative literal (leading '/', no '//', no backslash, no directive, no CR/LF/NUL).");
            }
            $out['redirect'] = $redirect;
        }

        if ($mode === 'gate') {
            $panel = (string) ($config['panel'] ?? 'phpmyadmin');
            if (!in_array($panel, self::DECOY_SESSION_PANELS, true)) {
                throw new RuntimeException("Template {$file}: behavior 'decoy-session' gate 'panel' must be one of " . implode('|', self::DECOY_SESSION_PANELS) . '.');
            }
            $out['panel'] = $panel;
            $domain = (string) ($config['domain'] ?? '');
            $this->assertKnownDirectives($domain, $file, true);
            $out['domain'] = $domain;
            $out['table_key'] = (string) ($config['table_key'] ?? 'users');
            if (isset($config['rows'])) {
                $out['rows'] = (int) $config['rows'];
            }
            // Opt-in Apache-DirectorySlash 301: a bare no-slash directory request redirects to the
            // trailing-slash form so the login page's relative form action resolves to an owned path.
            if (!empty($config['canonical_slash'])) {
                $out['canonical_slash'] = true;
            }
        }

        return $out;
    }

    /**
     * Normalize an `arith-eval` behavior config. Exactly one authored form is required:
     *  - fixed op:  `left` + `right` (capture keys) + `op` in {add,sub,mul};
     *  - expression: `expr` (a capture key) + `ops` (the operators authorized on that surface).
     * The `response` is directive- and static-header-checked like any base response; `max_operand`
     * is clamped to [1, ARITH_MAX_OPERAND] and `bind` defaults to 'result'. Runtime computation is
     * a hand-written integer parser (never eval) with no division — see TemplateAttackEmulator.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeArithEval(array $config, string $file): array
    {
        if (!isset($config['response'])) {
            throw new RuntimeException("Template {$file}: behavior 'arith-eval' must author a 'response'.");
        }
        $hasFixed = isset($config['left']) && isset($config['right']) && isset($config['op']);
        $hasExpr = isset($config['expr']) && isset($config['ops']);
        if ($hasFixed === $hasExpr) {
            throw new RuntimeException("Template {$file}: behavior 'arith-eval' needs EXACTLY one of (left+right+op) or (expr+ops).");
        }

        $out = ['response' => $this->normalizeBehaviorResponse((array) $config['response'], $file)];

        if ($hasFixed) {
            $op = (string) $config['op'];
            if (!in_array($op, self::ARITH_OPS, true)) {
                throw new RuntimeException("Template {$file}: arith-eval op '{$op}' is not one of " . implode('|', self::ARITH_OPS) . '.');
            }
            $out['left'] = (string) $config['left'];
            $out['right'] = (string) $config['right'];
            $out['op'] = $op;
        } else {
            $ops = [];
            foreach ((array) $config['ops'] as $op) {
                $op = (string) $op;
                if (!in_array($op, self::ARITH_OPS, true)) {
                    throw new RuntimeException("Template {$file}: arith-eval op '{$op}' is not one of " . implode('|', self::ARITH_OPS) . '.');
                }
                $ops[] = $op;
            }
            if ($ops === []) {
                throw new RuntimeException("Template {$file}: arith-eval 'ops' must list at least one of " . implode('|', self::ARITH_OPS) . '.');
            }
            $out['expr'] = (string) $config['expr'];
            $out['ops'] = $ops;
        }

        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND_DEFAULT;
        if ($max < 1) {
            $max = 1;
        }
        if ($max > self::ARITH_MAX_OPERAND) {
            $max = self::ARITH_MAX_OPERAND;
        }
        $out['max_operand'] = $max;
        $out['bind'] = isset($config['bind']) ? (string) $config['bind'] : 'result';

        return $out;
    }

    /** Hard ceiling on an expr-eval raw expression length; a larger authored max_len is clamped down. */
    private const EXPR_MAX_LEN = 256;

    /** The default expression-length cap when a template authors none. */
    private const EXPR_MAX_LEN_DEFAULT = 32;

    /**
     * Normalize an `expr-eval` behavior config. Evaluates a FULL arithmetic expression (grammar in
     * Support\SafeArithmetic: + - * / %, parentheses, unary sign, integer-only) held in the `expr`
     * capture, and binds the integer result into a capture key for reflection. Unlike arith-eval
     * (single closed op, no division), this is the SSTI-decoy engine: it accepts multi-op
     * expressions and division/modulo, with every unsafe case (div/mod by zero, overflow, oversized,
     * non-arithmetic) declining to null at runtime so the base response serves — never a 500, never
     * a code path that executes attacker input. `max_operand` is clamped to [1, ARITH_MAX_OPERAND]
     * and `max_len` to [1, EXPR_MAX_LEN]; `bind` defaults to 'result'. The `response` is directive-
     * and static-header-checked like any base response.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeExprEval(array $config, string $file): array
    {
        if (!isset($config['response'])) {
            throw new RuntimeException("Template {$file}: behavior 'expr-eval' must author a 'response'.");
        }
        if (!isset($config['expr']) || (string) $config['expr'] === '') {
            throw new RuntimeException("Template {$file}: behavior 'expr-eval' needs an 'expr' (the capture key holding the expression).");
        }

        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND;
        if ($max < 1) {
            $max = 1;
        }
        if ($max > self::ARITH_MAX_OPERAND) {
            $max = self::ARITH_MAX_OPERAND;
        }

        $maxLen = isset($config['max_len']) ? (int) $config['max_len'] : self::EXPR_MAX_LEN_DEFAULT;
        if ($maxLen < 1) {
            $maxLen = 1;
        }
        if ($maxLen > self::EXPR_MAX_LEN) {
            $maxLen = self::EXPR_MAX_LEN;
        }

        return [
            'response' => $this->normalizeBehaviorResponse((array) $config['response'], $file),
            'expr' => (string) $config['expr'],
            'bind' => isset($config['bind']) ? (string) $config['bind'] : 'result',
            'max_operand' => $max,
            'max_len' => $maxLen,
        ];
    }

    /** The closed engine enum for `ssti-render`; an authored value outside it is a build failure. */
    private const SSTI_ENGINES = ['jinja2', 'twig', 'freemarker', 'erb', 'javascript', 'mako'];

    /**
     * Normalize an `ssti-render` behavior config — the multi-fence SSTI decoy (tplmap-class
     * confirmation). Captures a whole template-fence RUN into the `surface` capture and, at runtime,
     * walks it fence-by-fence: each fence's inner is reduced to arithmetic and evaluated by
     * Support\SafeArithmetic (the SAME safe engine as expr-eval — byte-whitelisted, integer-only,
     * length/overflow-capped, NEVER eval/a template engine/a callback), the results concatenated and
     * bound for reflection. Any out-of-grammar byte, any non-arithmetic fence, or a surface over
     * `max_len` declines to null at runtime so the base response serves — never a 500, never a code
     * path that executes or reflects attacker input.
     *
     * `engines` is a CLOSED enum (unknown entry → build failure) that selects which code-authored
     * fence + shape recognisers fire; it is never turned into a regex at runtime. `max_operand` is
     * clamped to [1, ARITH_MAX_OPERAND] and `max_len` to [1, EXPR_MAX_LEN]; `bind` defaults to
     * 'rendered'. The `response` is directive- and static-header-checked like any base response.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeSstiRender(array $config, string $file): array
    {
        if (!isset($config['response'])) {
            throw new RuntimeException("Template {$file}: behavior 'ssti-render' must author a 'response'.");
        }
        if (!isset($config['surface']) || (string) $config['surface'] === '') {
            throw new RuntimeException("Template {$file}: behavior 'ssti-render' needs a 'surface' (the capture key holding the fence run).");
        }

        $max = isset($config['max_operand']) ? (int) $config['max_operand'] : self::ARITH_MAX_OPERAND;
        if ($max < 1) {
            $max = 1;
        }
        if ($max > self::ARITH_MAX_OPERAND) {
            $max = self::ARITH_MAX_OPERAND;
        }

        $maxLen = isset($config['max_len']) ? (int) $config['max_len'] : self::EXPR_MAX_LEN;
        if ($maxLen < 1) {
            $maxLen = 1;
        }
        if ($maxLen > self::EXPR_MAX_LEN) {
            $maxLen = self::EXPR_MAX_LEN;
        }

        $engines = [];
        foreach ((array) ($config['engines'] ?? []) as $engine) {
            $engine = (string) $engine;
            if (!in_array($engine, self::SSTI_ENGINES, true)) {
                throw new RuntimeException("Template {$file}: behavior 'ssti-render' has an unknown engine '{$engine}' (known: " . implode('|', self::SSTI_ENGINES) . ').');
            }
            if (!in_array($engine, $engines, true)) {
                $engines[] = $engine;
            }
        }
        if ($engines === []) {
            $engines = self::SSTI_ENGINES;
        }

        return [
            'response' => $this->normalizeBehaviorResponse((array) $config['response'], $file),
            'surface' => (string) $config['surface'],
            'bind' => isset($config['bind']) ? (string) $config['bind'] : 'rendered',
            'engines' => $engines,
            'max_operand' => $max,
            'max_len' => $maxLen,
        ];
    }

    /**
     * Normalize an `iterate` behavior config: a closed-set `parse`, an `item` template rendered once
     * per parsed sub-call, literal `wrap.open`/`wrap.close` body, and optional `response` (headers/
     * status), `empty.response`, and `fallback.response`. Every served node is directive-checked like
     * a base response; `max_items` is clamped to [1, MAX_ITERATE_ITEMS] so a template can never author
     * an amplifying fan-out. The parse regex itself is code-authored (see TemplateAttackEmulator), so
     * no attacker regex ever runs.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeIterate(array $config, string $file): array
    {
        $parse = (string) ($config['parse'] ?? '');
        if (!in_array($parse, self::ITERATE_PARSERS, true)) {
            throw new RuntimeException("Template {$file}: behavior 'iterate' needs a known 'parse' (" . implode('|', self::ITERATE_PARSERS) . ").");
        }
        if (!isset($config['item']['body'])) {
            throw new RuntimeException("Template {$file}: behavior 'iterate' must author an 'item.body'.");
        }

        $max = isset($config['max_items']) ? (int) $config['max_items'] : self::MAX_ITERATE_ITEMS;
        if ($max < 1) {
            $max = 1;
        }
        if ($max > self::MAX_ITERATE_ITEMS) {
            $max = self::MAX_ITERATE_ITEMS;
        }

        // wrap.open / wrap.close are served BODY (multi-line XML), so they get the directive-vocab
        // check but NOT the CR/LF static-header check — a body legitimately carries newlines.
        $wrap = (array) ($config['wrap'] ?? []);
        $open = (string) ($wrap['open'] ?? '');
        $close = (string) ($wrap['close'] ?? '');
        $this->assertKnownDirectives($open, $file);
        $this->assertKnownDirectives($close, $file);

        $out = [
            'source' => 'body',
            'parse' => $parse,
            'max_items' => $max,
            'item' => $this->normalizeBehaviorResponse((array) $config['item'], $file),
            'wrap' => ['open' => $open, 'close' => $close],
        ];

        if (isset($config['response'])) {
            $out['response'] = $this->normalizeBehaviorResponse((array) $config['response'], $file);
        }
        foreach (['empty', 'fallback'] as $k) {
            if (isset($config[$k]['response'])) {
                $out[$k] = ['response' => $this->normalizeBehaviorResponse((array) $config[$k]['response'], $file)];
            }
        }

        return $out;
    }

    /**
     * Normalize + validate one behavior-case `response` (body + headers + optional status). Mirrors
     * the base-response checks; status is the only addition (a case may choose its own status).
     *
     * @param array<string,mixed> $response
     * @return array<string,mixed>
     */
    private function normalizeBehaviorResponse(array $response, string $file): array
    {
        $headers = array_map('strval', (array) ($response['headers'] ?? []));
        $body = (string) ($response['body'] ?? '');

        $this->assertKnownDirectives($body, $file);
        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file, true);
            $this->assertKnownDirectives($value, $file, true);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }

        $out = [
            'headers' => $headers,
            'body' => $body,
        ];
        if (isset($response['status'])) {
            $out['status'] = $this->normalizeStatus($response['status'], $file);
        }

        return $out;
    }

    /**
     * An HTTP status must be an integer in 100–599; anything else (`status: banana` casts to 0)
     * would emit an invalid status line at runtime, so reject it at build.
     *
     * @param mixed $raw
     */
    private function normalizeStatus($raw, string $file): int
    {
        $status = (int) $raw;
        if ($status < 100 || $status > 599) {
            throw new RuntimeException("Template {$file}: response status '" . (string) $raw . "' is out of the 100-599 range.");
        }

        return $status;
    }

    /** A pre-filter literal below this length is too common to be worth a strpos before the regex. */
    private const MIN_LITERAL_LEN = 2;

    /**
     * Pick a required-literal pre-filter for a rule from its match conditions. Every condition
     * must hold (AND), so any single condition's required literal is required for the whole rule;
     * we take the longest (most selective) candidate. Returns null when none can be proven.
     *
     * @param array<int,array<string,mixed>> $match
     * @return array{lit:string,in:string,ci:bool}|null
     */
    private function requiredLiteral(array $match): ?array
    {
        $best = null;
        foreach ($match as $cond) {
            $lit = $this->conditionLiteral($cond);
            if ($lit === null || strlen($lit) < self::MIN_LITERAL_LEN) {
                continue;
            }
            if ($best === null || strlen($lit) > strlen($best['lit'])) {
                $best = [
                    'lit' => $lit,
                    'in' => (string) ($cond['in'] ?? 'request'),
                    'ci' => ($cond['ci'] ?? true) !== false,
                ];
            }
        }

        return $best;
    }

    /**
     * A literal that must appear in the surface for this one condition to hold, or null when
     * none is provable. A `contains` needle is required by definition; a `regex` yields its
     * mandatory literal prefix (only characters that every match must carry — see regexPrefix).
     *
     * @param array<string,mixed> $cond
     */
    private function conditionLiteral(array $cond): ?string
    {
        if (isset($cond['contains'])) {
            return (string) $cond['contains'];
        }
        if (isset($cond['regex'])) {
            return $this->regexPrefix((string) $cond['regex']);
        }

        return null;
    }

    /**
     * The mandatory literal prefix of a regex: the run of plain literal bytes every match must
     * start with, in the exact bytes the surface would carry. Conservative by construction — it
     * returns null (no pre-filter) rather than risk a literal that isn't truly required:
     *  - a top-level `|` means the pattern is an alternation of whole branches, so no single
     *    prefix is shared by every match — bail;
     *  - scanning stops at the first metacharacter, group, or character class, so the prefix
     *    never reaches into an optional/alternation construct;
     *  - a literal immediately quantified by `?`, `*`, or `{0,…}` is optional, so it is dropped.
     * Escaped punctuation (`\.`, `\$`, `\{`, …) unescapes to its literal byte; an escaped
     * alphanumeric (`\s`, `\d`, `\b`, …) is a class/anchor and ends the prefix.
     */
    private function regexPrefix(string $pattern): ?string
    {
        if ($this->hasTopLevelAlternation($pattern)) {
            return null;
        }

        $len = strlen($pattern);
        $i = 0;
        // A leading `^` anchors position only; the literal run starts after it.
        if ($i < $len && $pattern[$i] === '^') {
            $i++;
        }

        $prefix = '';
        while ($i < $len) {
            $ch = $pattern[$i];

            if ($ch === '\\') {
                if ($i + 1 >= $len) {
                    break;
                }
                $next = $pattern[$i + 1];
                // Escaped alphanumeric = character class or anchor (\s \d \w \b …): not a literal.
                if (ctype_alnum($next)) {
                    break;
                }
                $prefix .= $next;
                $i += 2;
                continue;
            }

            // Any bare metacharacter ends the plain-literal run.
            if (strpos('.^$*+?()[]{}|', $ch) !== false) {
                break;
            }

            // Look ahead: a quantifier binds to this single literal char.
            $q = $i + 1 < $len ? $pattern[$i + 1] : '';
            if ($q === '?' || $q === '*') {
                // This char is optional (0 or more) — not part of the required prefix.
                break;
            }
            if ($q === '{') {
                // `{m,n}` / `{m}`: required only when the minimum is at least 1.
                if ($this->quantifierMinIsZero(substr($pattern, $i + 1))) {
                    break;
                }
                $prefix .= $ch;
                break;
            }

            $prefix .= $ch;
            $i++;
        }

        return $prefix === '' ? null : $prefix;
    }

    /** True if a `{...}` quantifier at the start of $tail parses as min-zero (optional). */
    private function quantifierMinIsZero(string $tail): bool
    {
        // Multi-zero minimums are still zero: PCRE reads `{00}`, `{000}`, `{00,2}` as min 0.
        return preg_match('/^\{0+(?:,\d*)?\}/', $tail) === 1;
    }

    /**
     * True if $pattern carries a `|` at the top level (outside every group and character class),
     * i.e. it is an alternation of whole branches. Escapes are skipped so `\|`, `\(`, `\[` never
     * count.
     */
    private function hasTopLevelAlternation(string $pattern): bool
    {
        $len = strlen($pattern);
        $depth = 0;
        $inClass = false;
        for ($i = 0; $i < $len; $i++) {
            $ch = $pattern[$i];
            if ($ch === '\\') {
                $i++; // skip the escaped char
                continue;
            }
            if ($inClass) {
                if ($ch === ']') {
                    $inClass = false;
                }
                continue;
            }
            if ($ch === '[') {
                $inClass = true;
            } elseif ($ch === '(') {
                $depth++;
            } elseif ($ch === ')') {
                if ($depth > 0) {
                    $depth--;
                }
            } elseif ($ch === '|' && $depth === 0) {
                return true;
            }
        }

        return false;
    }

    private function assertValidRegex(string $pattern, bool $dotall, string $file): void
    {
        if (@preg_match('~' . $pattern . '~i' . ($dotall ? 's' : ''), '') === false) {
            throw new RuntimeException("Template {$file}: invalid regex: {$pattern}");
        }
    }

    /**
     * The directive vocabulary is closed. A `{{...}}` that isn't a known directive is almost
     * always a typo (`{{cannd.passwd}}`) which the runtime would emit as literal text — a
     * silently dead emulation. Reject it at build. (Escaped `{{{{ }}}}` is not a directive.)
     */
    private function assertKnownDirectives(string $text, string $file, bool $inHeader = false): void
    {
        $text = strtr($text, ['{{{{' => '', '}}}}' => '']);
        if (!preg_match_all('/\{\{\s*([^}]+?)\s*\}\}/', $text, $all)) {
            return;
        }
        foreach ($all[1] as $expr) {
            foreach (array_map('trim', explode('|', $expr)) as $part) {
                $known = false;
                foreach (DirectiveRenderer::KNOWN_PREFIXES as $prefix) {
                    if (strpos($part, $prefix) === 0) {
                        $known = true;
                        break;
                    }
                }
                if (!$known) {
                    throw new RuntimeException("Template {$file}: unknown directive '{{{$part}}}'. Vocabulary is closed — check for a typo.");
                }
                // persona.* is a CLOSED field set (unlike fake.NAME), so validate the whole path
                // — a mistyped field would render '' at runtime and silently drop a marker.
                if (strpos($part, 'persona.') === 0 && !in_array(substr($part, 8), PersonaIdentity::FIELDS, true)) {
                    throw new RuntimeException("Template {$file}: unknown persona field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // fake.person.* has a CLOSED sub-field set too (full/username/email), unlike a
                // plain fake.NAME — same reasoning as persona.* above.
                if (strpos($part, 'fake.person.') === 0 && !in_array(explode(':', substr($part, 12), 2)[0], DirectiveRenderer::PERSON_FIELDS, true)) {
                    throw new RuntimeException("Template {$file}: unknown fake.person field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // surface.* is a CLOSED form set (FP-0278): sitemap | disallow | noun:SLOT with SLOT in
                // SurfaceGraph::SLOTS — same reasoning as persona.* / fake.person.* above.
                if (strpos($part, 'surface.') === 0 && !self::isKnownSurfaceForm(substr($part, 8))) {
                    throw new RuntimeException("Template {$file}: unknown surface form '{{{$part}}}'. Forms are sitemap | disallow | noun:{c1,c2,d1,d2}.");
                }
                // urldecode-ascii:match.* is the bounded raw reflector slot for an HTML body. Its byte
                // class excludes CR/LF/NUL, so a header use would pass the runtime C8 guard silently —
                // this compile-time reject is the real body-only guard.
                if ($inHeader && strpos($part, 'urldecode-ascii:match.') === 0) {
                    throw new RuntimeException("Template {$file}: '{{{$part}}}' is body-only — the raw reflector slot must not appear in a header value.");
                }
                // attack.* is a CLOSED form set (FP-0279): sqli.{prefix,near,suffix} | page.{title,body}:{home,search}.
                if (strpos($part, 'attack.') === 0) {
                    if ($inHeader) {
                        // A warning frame carries a newline, so an attack.* body directive can never be a
                        // valid header value — reject it at compile time (belt-and-braces over the runtime
                        // fail-safe), so no artifact can smuggle a CR/LF into a header via this family.
                        throw new RuntimeException("Template {$file}: '{{{$part}}}' is body-only — the {{attack.*}} frames carry a newline and must not appear in a header value.");
                    }
                    if (!AttackBodies::isKnownForm(substr($part, 7))) {
                        throw new RuntimeException("Template {$file}: unknown attack form '{{{$part}}}'. Form set is closed — check for a typo.");
                    }
                }
            }
        }
    }

    /** True if $form is a valid {{surface.*}} form (the closed FP-0278 vocabulary). */
    private static function isKnownSurfaceForm(string $form): bool
    {
        if ($form === 'sitemap' || $form === 'disallow') {
            return true;
        }

        return strpos($form, 'noun:') === 0 && in_array(substr($form, 5), SurfaceGraph::SLOTS, true);
    }

    /**
     * A text/html response body that reflects a RAW request capture ({{match.N}}, {{urldecode:match.N}}
     * or {{urldecode-ascii:match.N}}) with no render-layer escape is a reflected-XSS-shaped surface. This build
     * refuses it unless the template either declares `reflects_input: true` (the deliberate reflector
     * marker — served only from an isolated origin) OR asserts `html_safe_captures: true` (every
     * capture class that can reach such a body provably excludes <>&"' — e.g. a `[\w.-]` filename, or a
     * behavior that reduces the capture to pure digits before binding it, as 43/45-ssti do). An escaped
     * reflection ({{html:match.N}} / {{xml:match.N}}) is always allowed. The walk covers the base
     * response AND every behavior's nested response body, so a behavior-bound reflection is caught too.
     * Compile-time only: `html_safe_captures` is never copied into the compiled rule (no artifact drift).
     *
     * @param array<string,mixed> $doc
     */
    private function assertHtmlReflectionSafe(array $doc, string $file): void
    {
        if (!empty($doc['reflects_input']) || !empty($doc['html_safe_captures'])) {
            return;
        }
        if ($this->htmlBodyReflectsRawCapture($doc)) {
            throw new RuntimeException("Template {$file}: a text/html response body reflects a raw request capture ({{match.*}}) with no render-layer escape. Use {{html:match.N}}, or declare 'reflects_input: true' (isolated-origin reflector) or 'html_safe_captures: true' (every capture class that reaches it provably excludes <>&\"').");
        }
    }

    /**
     * True if any response-shaped node in $node (recursively — base and behavior-nested responses) is
     * a text/html body carrying a raw {{match.*}} / {{urldecode:match.*}} reflection. Escaped
     * {{html:match.*}} / {{xml:match.*}} do not count.
     *
     * @param array<int|string,mixed> $node
     */
    private function htmlBodyReflectsRawCapture(array $node): bool
    {
        if (isset($node['body']) && (is_string($node['body']) || is_numeric($node['body']))) {
            $ctype = '';
            if (isset($node['headers']) && is_array($node['headers'])) {
                foreach ($node['headers'] as $hn => $hv) {
                    if (strcasecmp((string) $hn, 'Content-Type') === 0) {
                        $ctype = (string) $hv;
                    }
                }
            }
            if (stripos($ctype, 'text/html') === 0 && $this->bodyHasRawCapture((string) $node['body'])) {
                return true;
            }
        }
        foreach ($node as $child) {
            if (is_array($child) && $this->htmlBodyReflectsRawCapture($child)) {
                return true;
            }
        }

        return false;
    }

    /** True if a body carries a raw (unescaped) {{match.*}}, {{urldecode:match.*}} or {{urldecode-ascii:match.*}} directive. */
    private function bodyHasRawCapture(string $body): bool
    {
        if (strpos($body, '{{') === false) {
            return false;
        }
        $body = strtr($body, ['{{{{' => '', '}}}}' => '']);
        if (!preg_match_all('/\{\{\s*([^}]+?)\s*\}\}/', $body, $all)) {
            return false;
        }
        foreach ($all[1] as $expr) {
            foreach (array_map('trim', explode('|', $expr)) as $part) {
                if (strpos($part, 'match.') === 0 || strpos($part, 'urldecode:match.') === 0 || strpos($part, 'urldecode-ascii:match.') === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /** A static (non-directive) header must never carry CR/LF/NUL — that would be header splitting at author time. */
    private function assertStaticHeaderClean(string $name, string $value, string $file): void
    {
        $staticValue = preg_replace('/\{\{\s*[^}]+?\s*\}\}/', '', $value);
        if (preg_match('/[\r\n\x00]/', $name) === 1 || preg_match('/[\r\n\x00]/', (string) $staticValue) === 1) {
            throw new RuntimeException("Template {$file}: header '{$name}' has a CR/LF/NUL in its static text.");
        }
    }

    /**
     * Optional `expect:` — substrings the scanner's matcher needs. Render the response with
     * EMPTY captures + seed 0 and assert each is present, so a directive typo or a marker that
     * only exists via reflection (and thus wouldn't fire for a static probe) fails the build.
     *
     * @param array<string,mixed>  $doc
     * @param array<string,string> $headers
     */
    private function assertMarkers(array $doc, string $body, array $headers, string $file): void
    {
        if (!isset($doc['expect'])) {
            return;
        }
        $renderer = new DirectiveRenderer();
        $rendered = $renderer->render($body);
        foreach ($headers as $name => $value) {
            $rendered .= "\n" . $name . ': ' . $renderer->render($value);
        }
        foreach ((array) $doc['expect'] as $marker) {
            if (strpos($rendered, (string) $marker) === false) {
                throw new RuntimeException("Template {$file}: expected marker '{$marker}' not present in the rendered response.");
            }
        }
    }
}
