<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Attack\AttackBodies;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SurfaceGraph;
use Funnypot\Core\Template\DirectiveRenderer;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Compiles funnypot param-route templates (YAML) into the frozen bucket index the runtime
 * dispatches through. Build-time only (needs symfony/yaml); the emitted PHP array is pure
 * data, so the runtime stays PHP-only.
 *
 * A parameterized path (`/@fs/{path}`) can't be keyed in the exact O(1) store, so it is
 * modeled as an attack-tier-style rule: a compiled path `regex` + named `captures` + a normal
 * `response` body. The runtime dispatches on the first literal path segment (the bucket key),
 * so a param probe costs one hash probe + a bounded regex loop, never the linear attack scan.
 * The served entry is shaped exactly like an attack rule, so it reuses the request-aware render
 * path verbatim (renderRule / buildAttackFake / detectionForRule) — zero new render code.
 *
 * Path convention: `{name}` = one segment `(?P<name>[^/]+)`; a terminal `{name*}` spans the
 * rest `(?P<name>.+)`. The first segment must be a literal — it is the bucket key.
 *
 * Same build-time guards as the attack/route compilers: unique ids (within the param set AND
 * across the attack set — they share the runtime ruleById id-space), a closed directive
 * vocabulary, no CR/LF in static headers, and an optional `expect:` marker assertion.
 */
final class ParamRouteCompiler
{
    /** A single prefix bucket must stay small enough that its regex loop is cheap. */
    private const MAX_PATTERNS_PER_BUCKET = 32;

    /**
     * @param string   $dir         param-template dir (templates/param)
     * @param string[] $reservedIds ids already used by the attack set — a param id may not collide
     * @return array{schema:int,buckets:array<string,array<int,array<string,mixed>>>}
     */
    public function compile(string $dir, array $reservedIds = []): array
    {
        $files = TemplateGlob::yaml([$dir]);

        $reserved = array_flip(array_map('strval', $reservedIds));

        $rows = [];
        $seenIds = [];
        foreach ($files as $file) {
            $doc = Yaml::parseFile($file);
            if (!is_array($doc)) {
                throw new RuntimeException("Param template is not a mapping: {$file}");
            }
            $row = $this->normalize($doc, $file);

            $id = $row['entry']['id'];
            if (isset($seenIds[$id])) {
                throw new RuntimeException("Duplicate param template id '{$id}' ({$file} and {$seenIds[$id]}).");
            }
            if (isset($reserved[$id])) {
                throw new RuntimeException("Param template id '{$id}' ({$file}) collides with an attack rule id; the runtime looks rules up by id across both sets.");
            }
            $seenIds[$id] = $file;

            $rows[] = $row;
        }

        // Group by bucket, order first-match-wins within a bucket (priority, then id), cap size.
        $grouped = [];
        foreach ($rows as $row) {
            $grouped[$row['bucket']][] = $row;
        }

        $buckets = [];
        foreach ($grouped as $seg => $list) {
            usort($list, static function (array $a, array $b): int {
                return $a['priority'] <=> $b['priority'] ?: strcmp($a['entry']['id'], $b['entry']['id']);
            });
            if (count($list) > self::MAX_PATTERNS_PER_BUCKET) {
                throw new RuntimeException("Param bucket '{$seg}' has " . count($list) . ' patterns; the cap is ' . self::MAX_PATTERNS_PER_BUCKET . '.');
            }
            $buckets[$seg] = array_map(static function (array $row): array {
                return $row['entry'];
            }, $list);
        }

        return ['schema' => 1, 'buckets' => $buckets];
    }

    /**
     * @param array<string,mixed> $doc
     * @return array{bucket:string,entry:array<string,mixed>,priority:int}
     */
    private function normalize(array $doc, string $file): array
    {
        foreach (['id', 'param', 'response'] as $required) {
            if (!isset($doc[$required])) {
                throw new RuntimeException("Param template {$file} missing '{$required}'.");
            }
        }

        $param = (array) $doc['param'];
        if (!isset($param['path']) || (string) $param['path'] === '') {
            throw new RuntimeException("Param template {$file}: param.path is required.");
        }
        [$bucket, $regex, $captures] = $this->compilePath((string) $param['path'], $file);

        $method = strtoupper((string) ($param['method'] ?? 'GET'));
        if (preg_match('/^[A-Z]+$/', $method) !== 1) {
            throw new RuntimeException("Param template {$file}: param.method '{$method}' is not a bare HTTP method.");
        }

        $response = (array) $doc['response'];
        $headers = array_map('strval', (array) ($response['headers'] ?? []));
        $body = (string) ($response['body'] ?? '');
        if ($body === '') {
            throw new RuntimeException("Param template {$file}: response.body is required.");
        }

        $this->assertKnownDirectives($body, $file);
        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file, true);
            $this->assertKnownDirectives($value, $file, true);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }
        $this->assertMarkers($doc, $body, $headers, $file);
        $this->assertHtmlReflectionSafe($doc, $file);

        $entry = [
            'id' => (string) $doc['id'],
            'severity' => (string) ($doc['severity'] ?? 'high'),
            'tags' => array_map('strval', (array) ($doc['tags'] ?? [])),
            'status' => $this->normalizeStatus($doc['status'] ?? 200, $file),
            'method' => $method,
            'regex' => $regex,
            'captures' => $captures,
            'response' => [
                'headers' => $headers,
                'body' => $body,
            ],
        ];

        // Reflecting-decoy marker: this route echoes attacker request bytes into the served body.
        // The only guard against reflection inline is a text/plain Content-Type, which a host that
        // re-wraps the response can drop — so the runtime serves it only from an isolated origin
        // (Config::$isolatedOrigin), same fail-safe rule as the attack tier.
        if (!empty($doc['reflects_input'])) {
            $entry['reflects_input'] = true;
        }

        // The reflection class (Config::$reflectClasses knob key). Carried alongside reflects_input
        // so the per-class serve gate (Config::serveReflector) can target this entry specifically.
        if (isset($doc['reflect_class'])) {
            $entry['reflect_class'] = (string) $doc['reflect_class'];
        }

        // An optional named behavior primitive, same shape the attack tier renders. The base
        // `response` stays the ultimate fallback; this build knows `branch` and `traversal-read`.
        if (isset($doc['behavior'])) {
            $behavior = (string) $doc['behavior'];
            if ($behavior === 'branch') {
                $entry['behavior'] = 'branch';
                $entry['branch'] = $this->normalizeBranch((array) ($doc['branch'] ?? []), $file);
            } elseif ($behavior === 'traversal-read') {
                $entry['behavior'] = 'traversal-read';
                $entry['traversal-read'] = $this->normalizeTraversalRead((array) ($doc['traversal-read'] ?? []), $file);
            } else {
                throw new RuntimeException("Param template {$file}: unknown behavior '{$behavior}'. This build knows only 'branch' and 'traversal-read'.");
            }
        }

        return ['bucket' => $bucket, 'entry' => $entry, 'priority' => (int) ($doc['priority'] ?? 100)];
    }

    /**
     * Turn a param path template into a bucket key + anchored regex + ordered capture names.
     * `{name}` -> one segment; a terminal `{name*}` -> the rest of the path. The path must begin
     * with a literal segment (a root `{param}` is unbucketable and rejected).
     *
     * @return array{0:string,1:string,2:array<int,string>}
     */
    private function compilePath(string $path, string $file): array
    {
        if ($path[0] !== '/') {
            throw new RuntimeException("Param template {$file}: path must begin with '/': {$path}");
        }

        // The first path segment is the bucket key; it must be a literal (no placeholder).
        $firstSlash = strpos($path, '/', 1);
        $seg = $firstSlash === false ? substr($path, 1) : substr($path, 1, $firstSlash - 1);
        if ($seg === '' || strpos($seg, '{') !== false) {
            throw new RuntimeException("Param template {$file}: path must begin with a literal segment (a root {param} is unbucketable): {$path}");
        }

        $regex = '^';
        $captures = [];
        $len = strlen($path);
        $i = 0;
        while ($i < $len) {
            if ($path[$i] === '{') {
                $close = strpos($path, '}', $i);
                if ($close === false) {
                    throw new RuntimeException("Param template {$file}: unterminated '{' in path: {$path}");
                }
                $inner = substr($path, $i + 1, $close - $i - 1);
                $spanning = false;
                if ($inner !== '' && substr($inner, -1) === '*') {
                    $spanning = true;
                    $inner = substr($inner, 0, -1);
                }
                if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $inner) !== 1) {
                    throw new RuntimeException("Param template {$file}: invalid capture name '{$inner}' in path {$path} (must be a PCRE group name).");
                }
                if (in_array($inner, $captures, true)) {
                    throw new RuntimeException("Param template {$file}: duplicate capture name '{$inner}' in path {$path}.");
                }
                // A spanning `.+` swallows '/', so it may only be the final path token.
                if ($spanning && $close !== $len - 1) {
                    throw new RuntimeException("Param template {$file}: a spanning {{$inner}*} must be the last path segment: {$path}");
                }
                $captures[] = $inner;
                $regex .= '(?P<' . $inner . '>' . ($spanning ? '.+' : '[^/]+') . ')';
                $i = $close + 1;
            } else {
                $next = strpos($path, '{', $i);
                $end = $next === false ? $len : $next;
                $regex .= preg_quote(substr($path, $i, $end - $i), '~');
                $i = $end;
            }
        }
        $regex .= '$';

        if ($captures === []) {
            throw new RuntimeException("Param template {$file}: path has no {param} placeholder — key it in the exact store instead: {$path}");
        }
        // Author-only sanity: the emitted pattern must compile (it never sees attacker regex).
        if (@preg_match('~' . $regex . '~', '') === false) {
            throw new RuntimeException("Param template {$file}: compiled path regex is invalid: {$regex}");
        }

        return [$seg, $regex, $captures];
    }

    /**
     * Normalize a `branch` behavior config into the runtime shape (same as the attack compiler):
     * a non-empty `cases` list (each a `when` condition + a `response`) and an optional
     * `default.response`. Every authored response is directive- and static-header-checked.
     *
     * @param array<string,mixed> $branch
     * @return array<string,mixed>
     */
    private function normalizeBranch(array $branch, string $file): array
    {
        $cases = [];
        foreach ((array) ($branch['cases'] ?? []) as $case) {
            if (!is_array($case) || !isset($case['response'])) {
                throw new RuntimeException("Param template {$file}: each branch case must be a mapping with 'when' + 'response'.");
            }
            $cases[] = [
                'when' => $this->normalizeCondition((array) ($case['when'] ?? []), $file),
                'response' => $this->normalizeBehaviorResponse((array) $case['response'], $file),
            ];
        }
        if ($cases === []) {
            throw new RuntimeException("Param template {$file}: behavior 'branch' needs at least one entry in 'branch.cases'.");
        }

        $out = ['cases' => $cases];
        if (isset($branch['default'])) {
            $default = (array) $branch['default'];
            if (!isset($default['response'])) {
                throw new RuntimeException("Param template {$file}: branch 'default' must author a 'response'.");
            }
            $out['default'] = ['response' => $this->normalizeBehaviorResponse((array) $default['response'], $file)];
        }

        return $out;
    }

    /**
     * Normalize a `traversal-read` behavior config into the runtime shape: a non-empty `allow` list
     * of file targets (each exactly one of `suffix`|`basename` plus a `content` = the served fake
     * file) and an optional `default.content`. Every authored content body/headers is directive- and
     * static-header-checked, and its status normalized (default 200), same as the branch tier.
     *
     * @param array<string,mixed> $config
     * @return array<string,mixed>
     */
    private function normalizeTraversalRead(array $config, string $file): array
    {
        $allow = [];
        foreach ((array) ($config['allow'] ?? []) as $entry) {
            if (!is_array($entry)) {
                throw new RuntimeException("Param template {$file}: each traversal-read allow entry must be a mapping.");
            }
            $allow[] = $this->normalizeTraversalEntry($entry, $file);
        }
        if ($allow === []) {
            throw new RuntimeException("Param template {$file}: behavior 'traversal-read' needs at least one entry in 'traversal-read.allow'.");
        }

        $out = ['allow' => $allow];
        if (isset($config['default'])) {
            $default = (array) $config['default'];
            if (!isset($default['content'])) {
                throw new RuntimeException("Param template {$file}: traversal-read 'default' must author a 'content'.");
            }
            $out['default'] = ['content' => $this->normalizeTraversalContent((array) $default['content'], $file)];
        }

        return $out;
    }

    /**
     * Normalize one allow entry: exactly one of a non-empty `suffix` (segment-boundary match) or
     * `basename` (final-segment match), plus a `content`.
     *
     * @param array<string,mixed> $entry
     * @return array<string,mixed>
     */
    private function normalizeTraversalEntry(array $entry, string $file): array
    {
        $hasSuffix = isset($entry['suffix']) && (string) $entry['suffix'] !== '';
        $hasBasename = isset($entry['basename']) && (string) $entry['basename'] !== '';
        if ($hasSuffix === $hasBasename) {
            throw new RuntimeException("Param template {$file}: each traversal-read allow entry needs exactly one non-empty 'suffix' or 'basename'.");
        }
        if (!isset($entry['content'])) {
            throw new RuntimeException("Param template {$file}: each traversal-read allow entry needs a 'content'.");
        }

        $out = [];
        if ($hasSuffix) {
            $out['suffix'] = (string) $entry['suffix'];
        } else {
            $out['basename'] = (string) $entry['basename'];
        }
        $out['content'] = $this->normalizeTraversalContent((array) $entry['content'], $file);

        return $out;
    }

    /**
     * Normalize + validate one traversal-read `content` (body + headers + status default 200).
     *
     * @param array<string,mixed> $content
     * @return array<string,mixed>
     */
    private function normalizeTraversalContent(array $content, string $file): array
    {
        $headers = array_map('strval', (array) ($content['headers'] ?? []));
        $body = (string) ($content['body'] ?? '');

        $this->assertKnownDirectives($body, $file);
        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file, true);
            $this->assertKnownDirectives($value, $file, true);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }

        return [
            'headers' => $headers,
            'body' => $body,
            'status' => $this->normalizeStatus($content['status'] ?? 200, $file),
        ];
    }

    /**
     * Normalize one match/`when` condition into the runtime shape: `in` + `regex`|`contains`,
     * with the optional ci/dotall/capture switches carried through. Regexes are compile-checked.
     *
     * @param array<string,mixed> $cond
     * @return array<string,mixed>
     */
    private function normalizeCondition(array $cond, string $file): array
    {
        if (!isset($cond['in'])) {
            throw new RuntimeException("Param template {$file}: each condition needs 'in' + 'regex'|'contains'.");
        }
        $one = ['in' => (string) $cond['in']];
        if (isset($cond['regex'])) {
            $one['regex'] = (string) $cond['regex'];
            if (@preg_match('~' . $one['regex'] . '~i' . (($cond['dotall'] ?? false) ? 's' : ''), '') === false) {
                throw new RuntimeException("Param template {$file}: invalid regex: {$one['regex']}");
            }
        } elseif (isset($cond['contains'])) {
            $one['contains'] = (string) $cond['contains'];
        } else {
            throw new RuntimeException("Param template {$file}: condition needs 'regex' or 'contains'.");
        }
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
     * Normalize + validate one behavior-case `response` (body + headers + optional status).
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

        $out = ['headers' => $headers, 'body' => $body];
        if (isset($response['status'])) {
            $out['status'] = $this->normalizeStatus($response['status'], $file);
        }

        return $out;
    }

    /**
     * An HTTP status must be an integer in 100–599; anything else would emit an invalid status
     * line at runtime, so reject it at build.
     *
     * @param mixed $raw
     */
    private function normalizeStatus($raw, string $file): int
    {
        $status = (int) $raw;
        if ($status < 100 || $status > 599) {
            throw new RuntimeException("Param template {$file}: response status '" . (string) $raw . "' is out of the 100-599 range.");
        }

        return $status;
    }

    /** Closed directive vocabulary — a `{{...}}` that isn't known is a typo that would render as dead literal text. */
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
                    throw new RuntimeException("Param template {$file}: unknown directive '{{{$part}}}'. Vocabulary is closed — check for a typo.");
                }
                // rsa2048 is the closed JWKS modulus encoding (FP-0274): legal only as the exact
                // {{fake.jwks_n:rsa2048:342}} form; every other name/length and all volatile use is
                // rejected. The predicate is shared across all three compilers (one source of truth).
                $rsaErr = DirectiveRenderer::rsa2048FormError($part);
                if ($rsaErr !== null) {
                    throw new RuntimeException("Param template {$file}: {$rsaErr}");
                }
                // The chat-floor directives (FP-0275) are CLOSED: exact {{misdirect}}, {{chat.output_tokens}}
                // and {{chat.total_tokens:19}} only, body-only. `misdirect`/`chat.` stay in KNOWN_PREFIXES so
                // the exact forms clear the loop above; this shared predicate rejects every other shape.
                $chatErr = DirectiveRenderer::chatFloorFormError($part, $inHeader);
                if ($chatErr !== null) {
                    throw new RuntimeException("Param template {$file}: {$chatErr}");
                }
                if (strpos($part, 'persona.') === 0 && !in_array(substr($part, 8), PersonaIdentity::FIELDS, true)) {
                    throw new RuntimeException("Param template {$file}: unknown persona field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // fake.person.* has a CLOSED sub-field set too (full/username/email), unlike a
                // plain fake.NAME — same reasoning as persona.* above.
                if (strpos($part, 'fake.person.') === 0 && !in_array(explode(':', substr($part, 12), 2)[0], DirectiveRenderer::PERSON_FIELDS, true)) {
                    throw new RuntimeException("Param template {$file}: unknown fake.person field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // surface.* is a CLOSED form set (FP-0278): sitemap | disallow | noun:SLOT with SLOT in
                // SurfaceGraph::SLOTS — same reasoning as persona.* / fake.person.* above.
                if (strpos($part, 'surface.') === 0 && !self::isKnownSurfaceForm(substr($part, 8))) {
                    throw new RuntimeException("Param template {$file}: unknown surface form '{{{$part}}}'. Forms are sitemap | disallow | noun:{c1,c2,d1,d2}.");
                }
                // urldecode-ascii:match.* is the bounded raw reflector slot for an HTML body; its byte class
                // excludes CR/LF/NUL, so only this compile-time reject keeps it out of a header.
                if ($inHeader && strpos($part, 'urldecode-ascii:match.') === 0) {
                    throw new RuntimeException("Param template {$file}: '{{{$part}}}' is body-only — the raw reflector slot must not appear in a header value.");
                }
                // attack.* is a CLOSED form set (FP-0279): sqli.{prefix,near,suffix} | page.{title,body}:{home,search}.
                if (strpos($part, 'attack.') === 0) {
                    if ($inHeader) {
                        throw new RuntimeException("Param template {$file}: '{{{$part}}}' is body-only — the {{attack.*}} frames carry a newline and must not appear in a header value.");
                    }
                    if (!AttackBodies::isKnownForm(substr($part, 7))) {
                        throw new RuntimeException("Param template {$file}: unknown attack form '{{{$part}}}'. Form set is closed — check for a typo.");
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

    private function assertStaticHeaderClean(string $name, string $value, string $file): void
    {
        $staticValue = preg_replace('/\{\{\s*[^}]+?\s*\}\}/', '', $value);
        if (preg_match('/[\r\n\x00]/', $name) === 1 || preg_match('/[\r\n\x00]/', (string) $staticValue) === 1) {
            throw new RuntimeException("Param template {$file}: header '{$name}' has a CR/LF/NUL in its static text.");
        }
    }

    /**
     * A text/html response body reflecting a RAW request capture ({{match.*}} / {{urldecode:match.*}} /
     * {{urldecode-ascii:match.*}}) with no render-layer escape is a reflected-XSS-shaped surface — refused
     * unless the template declares `reflects_input: true` or asserts `html_safe_captures: true`. Escaped
     * {{html:match.*}} / {{xml:match.*}} are fine. Mirrors EmulatorCompiler::assertHtmlReflectionSafe; the
     * walk covers the base response and every behavior/traversal nested response. Compile-time only, never compiled in.
     *
     * @param array<string,mixed> $doc
     */
    private function assertHtmlReflectionSafe(array $doc, string $file): void
    {
        if (!empty($doc['reflects_input']) || !empty($doc['html_safe_captures'])) {
            return;
        }
        if ($this->htmlBodyReflectsRawCapture($doc)) {
            throw new RuntimeException("Param template {$file}: a text/html response body reflects a raw request capture ({{match.*}}) with no render-layer escape. Use {{html:match.N}}, or declare 'reflects_input: true' or 'html_safe_captures: true'.");
        }
    }

    /** @param array<int|string,mixed> $node */
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

    /**
     * Optional `expect:` — substrings the rendered response must carry when rendered with EMPTY
     * captures + seed 0. Guards against a directive typo silently dropping a believable marker;
     * targeting static text (e.g. `requested path: /@fs/`) keeps it stable under an empty render.
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
                throw new RuntimeException("Param template {$file}: expected marker '{$marker}' not present in the rendered response.");
            }
        }
    }
}
