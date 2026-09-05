<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Support\PathNormalizer;
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
        return $this->fragmentDirs([$dir]);
    }

    /**
     * Same as fragment(), across several dirs — hand-authored route templates plus the
     * machine-generated ones (templates/generated) fold into one index fragment.
     *
     * @param string[] $dirs
     * @return array{templates: array<string,array<string,mixed>>, routes: array<string,array<int,array<string,mixed>>>}
     */
    public function fragmentDirs(array $dirs): array
    {
        $files = TemplateGlob::yaml($dirs);

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
            // Optional persona weight: when a brand-new path also carries niche corpus detections,
            // a heavier tier makes THIS persona the one the seeded pick lands on far more often, so
            // the page reads coherently to most scanners. Uncapped keys keep the weight the synth
            // sets (merge-routes only re-tiers capped keys). Detection of the co-located templates is
            // unaffected — this biases which bundle is SERVED, never what is detected.
            if (isset($np['weight'])) {
                $bundle['w'] = max(1, (int) $np['weight']);
            }
            // Binary page (FP-0230): stamp `bin` so ResponseSynthesizer routes this bundle to the
            // rich emulator (which base64-decodes the body, or runs its binary_generator) and never
            // to minimal-synth (which would emit an empty body from the bundle's empty bw/nf). The
            // `response` block is a top-level sibling of `new_page` (same shape RouteEmulatorCompiler
            // reads); the bytes/generator live in the compiled route rule, so the bundle only needs
            // the marker.
            $response = (array) ($doc['response'] ?? []);
            if (isset($response['body_b64']) || !empty($response['binary']) || isset($response['binary_generator'])) {
                $bundle['bin'] = 1;
            }
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
