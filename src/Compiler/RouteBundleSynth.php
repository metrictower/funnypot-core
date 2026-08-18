<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Support\PathNormalizer;
use RuntimeException;
use Symfony\Component\Yaml\Yaml;

/**
 * Build-time: turns the `new_page` block of a route template into an index fragment — a
 * frozen bundle (schema-1 shape) plus a templates-table entry — for a brand-new product
 * page that has NO nuclei template. The fold step (funnypot merge-routes) merges this
 * fragment into the compiled index so respond() routes the page like any other.
 *
 * Enrich templates (which dress a bundle the nuclei index already routes to) carry no
 * new_page block and produce no fragment; the index is untouched for them.
 */
final class RouteBundleSynth
{
    /**
     * @return array{templates: array<string,array<string,mixed>>, routes: array<string,array<int,array<string,mixed>>>}
     */
    public function fragment(string $dir): array
    {
        $files = glob(rtrim($dir, '/') . '/*.yaml') ?: [];
        sort($files);

        $templates = [];
        $routes = [];
        foreach ($files as $file) {
            $doc = Yaml::parseFile($file);
            if (!is_array($doc) || !isset($doc['new_page'])) {
                continue;
            }
            $id = (string) ($doc['id'] ?? '');
            if ($id === '') {
                throw new RuntimeException("new_page in {$file} needs an id.");
            }
            $np = (array) $doc['new_page'];
            $method = strtoupper((string) ($np['method'] ?? 'GET'));
            $paths = array_values(array_map('strval', (array) ($np['paths'] ?? [])));
            if ($paths === []) {
                throw new RuntimeException("new_page in {$file} needs at least one path.");
            }

            $bundle = [
                's' => (int) ($np['status'] ?? 200),
                'bw' => array_values(array_map('strval', (array) ($np['body_words'] ?? []))),
                'nf' => array_values(array_map('strval', (array) ($np['forbidden'] ?? []))),
                'pid' => $id,
                'sev' => (string) ($np['severity'] ?? 'high'),
                'sig' => (int) ($np['sig'] ?? 0),
                't' => [$id],
            ];
            $typed = (array) ($np['typed_headers'] ?? []);
            if ($typed !== []) {
                $bundle['th'] = [];
                foreach ($typed as $name => $subs) {
                    $bundle['th'][(string) $name] = array_values(array_map('strval', (array) $subs));
                }
            }

            if (isset($templates[$id])) {
                throw new RuntimeException("Duplicate new_page id '{$id}' in {$file}.");
            }
            $templates[$id] = [
                'sev' => $bundle['sev'],
                'tags' => array_values(array_map('strval', (array) ($np['tags'] ?? []))),
                'name' => (string) ($np['name'] ?? $id),
            ];

            foreach ($paths as $path) {
                $routes[PathNormalizer::key($method, $path)][] = $bundle;
            }
        }

        return ['templates' => $templates, 'routes' => $routes];
    }
}
