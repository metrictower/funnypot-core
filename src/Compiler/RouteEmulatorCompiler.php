<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Template\DirectiveRenderer;
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
     * @return array<int,array<string,mixed>>
     */
    public function compile(string $dir): array
    {
        $files = glob(rtrim($dir, '/') . '/*.yaml') ?: [];
        sort($files);

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
        $headers = array_map('strval', (array) ($response['headers'] ?? []));
        $body = (string) ($response['body'] ?? '');
        if ($body === '') {
            throw new RuntimeException("Route template {$file}: response.body is required.");
        }

        $this->assertKnownDirectives($body, $file);
        foreach ($headers as $name => $value) {
            $this->assertKnownDirectives((string) $name, $file);
            $this->assertKnownDirectives($value, $file);
            $this->assertStaticHeaderClean((string) $name, $value, $file);
        }
        $this->assertMarkers($doc, $body, $headers, $file);

        $rule = [
            'id' => (string) $doc['id'],
            'match' => $match,
            'body' => $body,
            'headers' => $headers,
            '_priority' => (int) ($doc['priority'] ?? 100),
        ];
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
     * @param array<string,mixed> $match
     * @return array<string,array<int,string>>
     */
    private function normalizeMatch(array $match, string $file): array
    {
        $out = [];
        foreach (['template_needle', 'pid', 'body_word_contains'] as $axis) {
            if (isset($match[$axis]) && (array) $match[$axis] !== []) {
                $out[$axis] = array_values(array_map('strval', (array) $match[$axis]));
            }
        }
        if ($out === []) {
            throw new RuntimeException("Route template {$file}: match needs at least one of template_needle / pid / body_word_contains.");
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
                    throw new RuntimeException("Route template {$file}: unknown directive '{{{$part}}}'. Vocabulary is closed — check for a typo.");
                }
            }
        }
    }

    private function assertStaticHeaderClean(string $name, string $value, string $file): void
    {
        $staticValue = preg_replace('/\{\{\s*[^}]+?\s*\}\}/', '', $value);
        if (preg_match('/[\r\n\x00]/', $name) === 1 || preg_match('/[\r\n\x00]/', (string) $staticValue) === 1) {
            throw new RuntimeException("Route template {$file}: header '{$name}' has a CR/LF/NUL in its static text.");
        }
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
