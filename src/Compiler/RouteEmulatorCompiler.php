<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Attack\AttackBodies;
use Funnypot\Core\Response\BinaryBodyGeneratorRegistry;
use Funnypot\Core\SchemaVersion;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Support\SurfaceGraph;
use Funnypot\Core\Template\DirectiveRenderer;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Compiles funnypot route templates (YAML) into the frozen rules array the runtime
 * RouteTemplateEmulator interprets. Build-time only (needs symfony/yaml); the emitted PHP
 * array is pure data, so the runtime stays PHP-only.
 *
 * A route template dresses a bundle the compiled index already routes to (enrich). Rule
 * order = first-match-wins; control it with `priority` (lower first), then `id`. Same
 * build-time guards as the attack compiler: unique ids, closed directive vocabulary, no
 * CR/LF in static headers, and an optional `expect:` marker assertion.
 */
final class RouteEmulatorCompiler
{
    /**
     * The closed `response` key set. An unknown key fails the build instead of being silently
     * ignored, so a would-be generator argument, class name or callback can never ride along in a
     * rule artifact. `binary` is the legacy marker that forces body_b64 handling.
     */
    public const RESPONSE_KEYS = ['headers', 'body', 'body_b64', 'binary', 'binary_generator'];

    /**
     * Prefix of the compiled `body` a binary_generator rule carries. Deliberately outside the base64
     * alphabet: a runtime that predates generators takes the base64 branch for every bin rule, and a
     * strict decode of this sentinel returns false, so it declines to the host 404 — whereas an empty
     * body would decode to '' and serve a 200 empty attachment. The current runtime resolves
     * `binary_generator` before ever reading `body`.
     */
    public const GENERATOR_BODY_SENTINEL = '!';

    /**
     * @return array<int,array<string,mixed>>
     */
    public function compile(string $dir): array
    {
        return $this->compileDirs([$dir]);
    }

    /**
     * Compile several template dirs into one first-match-wins rule set. Order across dirs
     * doesn't matter — `priority` (then `id`) is the real key — so hand-authored route
     * templates and machine-generated ones (templates/generated) sort together correctly.
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
                throw new RuntimeException("Route template is not a mapping: {$file}");
            }
            $rule = $this->normalize($doc, $file);

            $id = $rule['id'];
            if (isset($seenIds[$id])) {
                throw new RuntimeException("Duplicate route template id '{$id}' ({$file} and {$seenIds[$id]}).");
            }
            $seenIds[$id] = $file;

            $rules[] = $rule;
        }

        usort($rules, static function (array $a, array $b): int {
            return $a['_priority'] <=> $b['_priority'] ?: strcmp($a['id'], $b['id']);
        });

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
        foreach (['id', 'response'] as $required) {
            if (!isset($doc[$required])) {
                throw new RuntimeException("Route template {$file} missing '{$required}'.");
            }
        }

        $version = (int) ($doc['version'] ?? 1);
        if ($version > SchemaVersion::CURRENT) {
            throw new RuntimeException("Route template {$file}: schema version {$version} exceeds the engine's supported schema " . SchemaVersion::CURRENT . " — refusing to compile (upgrade funnypot-core).");
        }

        // A new_page template routes to its OWN synthesized bundle (pid = id), so it may omit
        // match — the selector is auto-filled. Enrich templates must declare match explicitly.
        $matchDoc = (array) ($doc['match'] ?? []);
        if (isset($doc['new_page']) && $matchDoc === []) {
            $matchDoc = ['pid' => [(string) $doc['id']]];
        }
        if ($matchDoc === []) {
            throw new RuntimeException("Route template {$file} missing 'match'.");
        }
        $match = $this->normalizeMatch($matchDoc, $file);

        $response = (array) $doc['response'];
        foreach (array_keys($response) as $key) {
            if (!in_array((string) $key, self::RESPONSE_KEYS, true)) {
                throw new RuntimeException("Route template {$file}: unknown response key '{$key}'. The set is closed: " . implode(' | ', self::RESPONSE_KEYS) . '.');
            }
        }
        $headers = array_map('strval', (array) ($response['headers'] ?? []));

        // Exactly one body source: `body` (directive text), `body_b64` (static bytes) or
        // `binary_generator` (a built-in writer, resolved at serve time). Both binary arms are
        // detected FIRST — BEFORE the empty-`response.body` throw below — because a binary rule
        // legitimately has no `response.body`.
        $generator = array_key_exists('binary_generator', $response)
            ? $this->normalizeBinaryGenerator($response, $file)
            : null;

        // Binary rule (FP-0230): an image/favicon body is stored base64-at-rest as
        // `response.body_b64` (a `binary: true` marker forces it too) and decoded at serve. base64
        // is opaque ASCII, not directive text, so the directive/marker body guards are skipped for
        // it; header text is still guarded exactly as for a text rule. Storing base64 (never raw
        // bytes) keeps every compiled artifact ASCII-clean under var_export.
        $isBinary = $generator !== null || isset($response['body_b64']) || !empty($response['binary']);
        if ($generator !== null) {
            $body = self::GENERATOR_BODY_SENTINEL . $generator;
        } elseif ($isBinary) {
            if (isset($response['body'])) {
                throw new RuntimeException("Route template {$file}: a binary rule carries response.body_b64, not response.body (both present).");
            }
            $body = (string) ($response['body_b64'] ?? '');
            if ($body === '' || base64_decode($body, true) === false) {
                throw new RuntimeException("Route template {$file}: response.body_b64 must be non-empty, strict base64.");
            }
        } else {
            $body = (string) ($response['body'] ?? '');
            if ($body === '') {
                throw new RuntimeException("Route template {$file}: response.body is required.");
            }
            $this->assertKnownDirectives($body, $file);
        }

        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file, true);
            $this->assertKnownDirectives($value, $file, true);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }
        if (!$isBinary) {
            $this->assertMarkers($doc, $body, $headers, $file);
        }
        $this->assertHtmlReflectionSafe($doc, $file);

        $rule = [
            'id' => (string) $doc['id'],
            'match' => $match,
            'body' => $body,
            'headers' => $headers,
            '_priority' => (int) ($doc['priority'] ?? 100),
        ];
        if ($isBinary) {
            // Stamp the runtime marker: RouteTemplateEmulator serves the bytes verbatim (generated
            // or base64-decoded) and ResponseSynthesizer never routes the bundle to minimal synth.
            $rule['bin'] = 1;
        }
        if ($generator !== null) {
            $rule['binary_generator'] = $generator;
        }
        if (isset($doc['taunt'])) {
            $rule['taunt'] = $this->normalizeTaunt((array) $doc['taunt'], $file);
        }
        if (isset($doc['set_cookie'])) {
            $cookie = (string) $doc['set_cookie'];
            if (preg_match('/[^A-Za-z0-9_.\-]/', $cookie) === 1) {
                throw new RuntimeException("Route template {$file}: set_cookie must be a bare cookie name (got '{$cookie}').");
            }
            $rule['set_cookie'] = $cookie;
        }

        return $rule;
    }

    /**
     * `response.binary_generator` is a bare string naming one built-in generator, exactly (no trim).
     * A mapping, list, number or unknown token is rejected: YAML selects a generator, it never
     * supplies a class, callback, options or template text.
     *
     * @param array<string,mixed> $response
     */
    private function normalizeBinaryGenerator(array $response, string $file): string
    {
        if (isset($response['body']) || isset($response['body_b64'])) {
            throw new RuntimeException("Route template {$file}: response.binary_generator is exclusive with response.body / response.body_b64 — exactly one of the three.");
        }
        $id = $response['binary_generator'];
        if (!is_string($id) || !in_array($id, BinaryBodyGeneratorRegistry::IDS, true)) {
            $shown = is_string($id) ? $id : gettype($id);
            throw new RuntimeException("Route template {$file}: unknown binary_generator '{$shown}'. The registry is closed: " . implode(' | ', BinaryBodyGeneratorRegistry::IDS) . '.');
        }

        return $id;
    }

    /**
     * @param array<string,mixed> $match
     * @return array<string,array<int,string>>
     */
    private function normalizeMatch(array $match, string $file): array
    {
        // The match vocabulary is closed: an unknown key is a typo that would silently widen or
        // narrow selection (normalizeMatch used to ignore it). template_needle/pid/body_word_contains
        // are OR selector axes; route_key is a conjunctive guard.
        foreach (array_keys($match) as $key) {
            if (!in_array((string) $key, ['template_needle', 'pid', 'body_word_contains', 'route_key'], true)) {
                throw new RuntimeException("Route template {$file}: unknown match key '{$key}'. The set is closed: template_needle | pid | body_word_contains | route_key.");
            }
        }

        $out = [];
        foreach (['template_needle', 'pid', 'body_word_contains'] as $axis) {
            if (isset($match[$axis]) && (array) $match[$axis] !== []) {
                $out[$axis] = array_values(array_map('strval', (array) $match[$axis]));
            }
        }
        // route_key is a GUARD, never a standalone selector — a route-key-only rule would dress every
        // bundle that ever resolves at that key. Require a selector axis before adding the guard.
        if ($out === []) {
            throw new RuntimeException("Route template {$file}: match needs at least one of template_needle / pid / body_word_contains.");
        }
        if (isset($match['route_key']) && (array) $match['route_key'] !== []) {
            $out['route_key'] = $this->normalizeRouteKeys((array) $match['route_key'], $file);
        }

        return $out;
    }

    /**
     * Validate `match.route_key`: each entry is an exact compiled store key — an uppercase supported
     * method, one ASCII space, an absolute path, no query/fragment/control byte — deduplicated and
     * non-empty. This is the '<METHOD> <path>' shape Honeypot resolves before synthesis, so a
     * malformed entry could never match a real handle and is rejected at build time.
     *
     * @param array<int,mixed> $keys
     * @return array<int,string>
     */
    private function normalizeRouteKeys(array $keys, string $file): array
    {
        $out = [];
        $seen = [];
        foreach ($keys as $raw) {
            $key = (string) $raw;
            if ($key === '') {
                throw new RuntimeException("Route template {$file}: match.route_key entries must be non-empty.");
            }
            if (preg_match('~^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS|TRACE) /[^\s?#\x00-\x1f]*$~', $key) !== 1) {
                throw new RuntimeException("Route template {$file}: match.route_key '{$key}' must be '<METHOD> /path' — an uppercase supported method, one space, an absolute path, no query/fragment/control byte.");
            }
            if (isset($seen[$key])) {
                throw new RuntimeException("Route template {$file}: duplicate match.route_key '{$key}'.");
            }
            $seen[$key] = true;
            $out[] = $key;
        }

        return $out;
    }

    /**
     * @param array<string,mixed> $taunt
     * @return array<string,string>
     */
    private function normalizeTaunt(array $taunt, string $file): array
    {
        $mode = (string) ($taunt['mode'] ?? 'line');
        if (!in_array($mode, ['line', 'block', 'inline_field'], true)) {
            throw new RuntimeException("Route template {$file}: taunt.mode must be line | block | inline_field.");
        }
        $out = ['mode' => $mode];
        foreach (['open', 'close', 'key'] as $k) {
            if (isset($taunt[$k])) {
                $out[$k] = (string) $taunt[$k];
            }
        }

        return $out;
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
                    throw new RuntimeException("Route template {$file}: unknown directive '{{{$part}}}'. Vocabulary is closed — check for a typo.");
                }
                // rsa2048 is the closed JWKS modulus encoding (FP-0274): legal only as the exact
                // {{fake.jwks_n:rsa2048:342}} form; every other name/length and all volatile use is
                // rejected. The predicate is shared across all three compilers (one source of truth).
                $rsaErr = DirectiveRenderer::rsa2048FormError($part);
                if ($rsaErr !== null) {
                    throw new RuntimeException("Route template {$file}: {$rsaErr}");
                }
                // The chat-floor directives (FP-0275) are CLOSED: exact {{misdirect}}, {{chat.output_tokens}}
                // and {{chat.total_tokens:19}} only, body-only. `misdirect`/`chat.` stay in KNOWN_PREFIXES so
                // the exact forms clear the loop above; this shared predicate rejects every other shape.
                $chatErr = DirectiveRenderer::chatFloorFormError($part, $inHeader);
                if ($chatErr !== null) {
                    throw new RuntimeException("Route template {$file}: {$chatErr}");
                }
                // persona.* is a CLOSED field set (unlike fake.NAME), so validate the whole path
                // — a mistyped field would render '' at runtime and silently drop a marker.
                if (strpos($part, 'persona.') === 0 && !in_array(substr($part, 8), PersonaIdentity::FIELDS, true)) {
                    throw new RuntimeException("Route template {$file}: unknown persona field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // fake.person.* has a CLOSED sub-field set too (full/username/email), unlike a
                // plain fake.NAME — same reasoning as persona.* above.
                if (strpos($part, 'fake.person.') === 0 && !in_array(explode(':', substr($part, 12), 2)[0], DirectiveRenderer::PERSON_FIELDS, true)) {
                    throw new RuntimeException("Route template {$file}: unknown fake.person field '{{{$part}}}'. Field set is closed — check for a typo.");
                }
                // surface.* is a CLOSED form set (FP-0278): sitemap | disallow | noun:SLOT with SLOT in
                // SurfaceGraph::SLOTS. An unknown form would render '' and silently drop the seeded
                // surface graph — same reasoning as persona.* / fake.person.* above.
                if (strpos($part, 'surface.') === 0 && !self::isKnownSurfaceForm(substr($part, 8))) {
                    throw new RuntimeException("Route template {$file}: unknown surface form '{{{$part}}}'. Forms are sitemap | disallow | noun:{c1,c2,d1,d2}.");
                }
                // urldecode-ascii:match.* is the bounded raw reflector slot for an HTML body; its byte class
                // excludes CR/LF/NUL, so only this compile-time reject keeps it out of a header.
                if ($inHeader && strpos($part, 'urldecode-ascii:match.') === 0) {
                    throw new RuntimeException("Route template {$file}: '{{{$part}}}' is body-only — the raw reflector slot must not appear in a header value.");
                }
                // attack.* is a CLOSED form set (FP-0279): sqli.{prefix,near,suffix} | page.{title,body}:{home,search}.
                if (strpos($part, 'attack.') === 0) {
                    if ($inHeader) {
                        throw new RuntimeException("Route template {$file}: '{{{$part}}}' is body-only — the {{attack.*}} frames carry a newline and must not appear in a header value.");
                    }
                    if (!AttackBodies::isKnownForm(substr($part, 7))) {
                        throw new RuntimeException("Route template {$file}: unknown attack form '{{{$part}}}'. Form set is closed — check for a typo.");
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
            throw new RuntimeException("Route template {$file}: header '{$name}' has a CR/LF/NUL in its static text.");
        }
    }

    /**
     * A text/html response body reflecting a RAW request capture ({{match.*}} / {{urldecode:match.*}} /
     * {{urldecode-ascii:match.*}}) with no render-layer escape is a reflected-XSS-shaped surface — refused
     * unless the template declares `reflects_input: true` or asserts `html_safe_captures: true`. Escaped
     * {{html:match.*}} / {{xml:match.*}} are fine. Mirrors EmulatorCompiler::assertHtmlReflectionSafe (same
     * closed lint on the route tier); compile-time only, never copied into the compiled rule.
     *
     * @param array<string,mixed> $doc
     */
    private function assertHtmlReflectionSafe(array $doc, string $file): void
    {
        if (!empty($doc['reflects_input']) || !empty($doc['html_safe_captures'])) {
            return;
        }
        if ($this->htmlBodyReflectsRawCapture($doc)) {
            throw new RuntimeException("Route template {$file}: a text/html response body reflects a raw request capture ({{match.*}}) with no render-layer escape. Use {{html:match.N}}, or declare 'reflects_input: true' or 'html_safe_captures: true'.");
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
     * Optional `expect:` — substrings the rendered response must carry (seed 0, empty captures).
     * Guards against a directive typo silently dropping a believable marker.
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
                throw new RuntimeException("Route template {$file}: expected marker '{$marker}' not present in the rendered response.");
            }
        }
    }
}
