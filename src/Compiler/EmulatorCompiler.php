<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

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
        $files = glob(rtrim($dir, '/') . '/*.yaml') ?: [];
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
            if (!is_array($cond) || !isset($cond['in'])) {
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
            $match[] = $one;
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

        return [
            'id' => (string) $doc['id'],
            'severity' => (string) ($doc['severity'] ?? 'high'),
            'tags' => array_map('strval', (array) ($doc['tags'] ?? [])),
            'status' => (int) ($doc['status'] ?? 200),
            'match' => $match,
            'response' => [
                'headers' => $headers,
                'body' => $body,
            ],
            '_priority' => (int) ($doc['priority'] ?? 100),
        ];
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
