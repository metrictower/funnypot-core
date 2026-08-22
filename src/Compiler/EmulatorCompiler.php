<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Support\PersonaIdentity;
use Funnypot\Template\DirectiveRenderer;
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
        $files = [];
        foreach ($dirs as $dir) {
            foreach (glob(rtrim($dir, '/') . '/*.yaml') ?: [] as $file) {
                $files[] = $file;
            }
        }
        sort($files);

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
            $this->assertKnownDirectives((string) $name, $file);
            $this->assertKnownDirectives($value, $file);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }
        $this->assertMarkers($doc, $body, $headers, $file);

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

        // An optional named behavior primitive. The base `response` above stays the ultimate
        // fallback; the behavior only picks the content when it fires. Unknown names are a build
        // failure — this milestone ships only `branch` (the other primitives are deferred).
        if (isset($doc['behavior'])) {
            $behavior = (string) $doc['behavior'];
            if ($behavior !== 'branch') {
                throw new RuntimeException("Template {$file}: unknown behavior '{$behavior}'. This build knows only 'branch'.");
            }
            $rule['behavior'] = 'branch';
            $rule['branch'] = $this->normalizeBranch((array) ($doc['branch'] ?? []), $file);
        }

        return $rule;
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
            $this->assertKnownDirectives((string) $name, $file);
            $this->assertKnownDirectives($value, $file);
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
    private function assertKnownDirectives(string $text, string $file): void
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
            }
        }
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
