<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

use Funnypot\Support\PathNormalizer;

/**
 * Orchestrates the offline build:
 *   load http/*.yaml → Gate A → Gate B (classify) → group by (method, normalized path)
 *   → conflict-partition each group into persona bundles → emit the schema-1 index.
 *
 * Produces the compiled index array plus manifest and skipped sidecars. Output is a
 * pure literal array (no objects/closures), loadable by PhpArrayStore.
 */
final class Compiler
{
    private TemplateLoader $loader;
    private ClusterableFilter $gateA;
    private Classifier $gateB;
    private BundlePartitioner $partitioner;
    private PersonaCap $cap;

    public function __construct()
    {
        $this->loader = new TemplateLoader();
        $this->gateA = new ClusterableFilter();
        $this->gateB = new Classifier();
        $this->partitioner = new BundlePartitioner();
        $this->cap = new PersonaCap();
    }

    /**
     * @param array<string,mixed> $meta upstream tag/sha etc. for the manifest
     * @return array{index:array,manifest:array,skipped:array,stats:array}
     */
    public function compile(string $templatesDir, array $meta = []): array
    {
        $files = $this->enumerate($templatesDir);

        $templatesMeta = [];   // id => [sev,tags,name]
        $groups = [];          // routeKey => SatisfyPlan[]
        $rootKeys = [];        // routeKey => true when path is '/'
        $skipped = [];         // id => reason
        $stats = [
            'total' => 0,
            'gateA' => [],
            'gateB' => [],
            'in' => 0,
            'parse_errors' => 0,
        ];

        foreach ($files as $file) {
            $stats['total']++;

            try {
                $t = $this->loader->loadFile($file);
            } catch (\Throwable $e) {
                $stats['parse_errors']++;
                $skipped['@' . basename($file)] = 'load:parse-error';
                $this->bump($stats['gateA'], 'load:parse-error');
                continue;
            }

            $reasonA = $this->gateA->reject($t);
            if ($reasonA !== null) {
                $skipped[$t->id] = $reasonA;
                $this->bump($stats['gateA'], $reasonA);
                continue;
            }

            $classified = $this->gateB->classify($t);
            if (!$classified->in) {
                $skipped[$t->id] = $classified->reason;
                $this->bump($stats['gateB'], $classified->reason);
                continue;
            }

            $stats['in']++;
            $plan = $classified->plan;
            $templatesMeta[$t->id] = [
                'sev' => $t->severity,
                'tags' => $t->tags,
                'name' => $t->name,
            ];

            foreach ($this->routeKeys($t) as $key => $isRoot) {
                $groups[$key][$t->id] = $plan; // dedupe a template's repeated key by id
                if ($isRoot) {
                    $rootKeys[$key] = true;
                }
            }
        }

        [$routes, $routeStats] = $this->buildRoutes($groups, $rootKeys, $templatesMeta);

        $index = [
            'schema' => 1,
            'manifest' => $this->manifest($meta, $stats, $routeStats, count($templatesMeta)),
            'templates' => $templatesMeta,
            'routes' => $routes,
        ];

        $stats = array_merge($stats, $routeStats);

        return [
            'index' => $index,
            'manifest' => $index['manifest'],
            'skipped' => $skipped,
            'stats' => $stats,
        ];
    }

    /**
     * @return string[]
     */
    private function enumerate(string $dir): array
    {
        $files = [];
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $f) {
            if ($f->isFile() && strtolower($f->getExtension()) === 'yaml') {
                $files[] = $f->getPathname();
            }
        }
        sort($files); // deterministic build order

        return $files;
    }

    /**
     * Every routable path of a template → its route key, flagged if it is the site root.
     *
     * @return array<string,bool>
     */
    private function routeKeys(LoadedTemplate $t): array
    {
        $keys = [];
        foreach ($t->paths as $path) {
            $target = ClusterableFilter::pathTarget($path);
            if ($target === null) {
                continue; // Gate A already vetted paths; guard defensively
            }
            $normalized = PathNormalizer::normalize($target);
            $key = PathNormalizer::key($t->method, $normalized);
            $keys[$key] = ($normalized === '/');
        }

        return $keys;
    }

    /**
     * @param array<string,SatisfyPlan[]>                               $groups
     * @param array<string,bool>                                        $rootKeys
     * @param array<string,array{sev:string,tags:string[],name:string}> $templatesMeta
     * @return array{0:array,1:array}
     */
    private function buildRoutes(array $groups, array $rootKeys, array $templatesMeta): array
    {
        ksort($groups);
        $routes = [];
        $multiBundle = 0;
        $largest = 0;
        $bundleTotal = 0;
        $capped = [];

        foreach ($groups as $key => $plans) {
            $bundles = $this->partitioner->partition(array_values($plans));
            $sig = isset($rootKeys[$key]) ? 1 : 0;
            $count = count($bundles);

            if ($count > PersonaCap::N) {
                // Mega-collision key: keep FULL detect coverage on 'd', cap + rank the
                // served ('b') set, and stamp each kept bundle with a selection weight.
                $detectIds = $this->collectDetectIds($bundles);
                $capResult = $this->cap->cap($bundles, $templatesMeta);

                $frozen = [];
                foreach ($capResult['kept'] as $bundle) {
                    $out = $this->freezeBundle($bundle, $sig);
                    $out['w'] = $this->cap->weight($bundle, $templatesMeta);
                    $frozen[] = $out;
                }
                $routes[$key] = ['d' => $detectIds, 'b' => $frozen];

                $capped[$key] = [
                    'bundles_before' => $count,
                    'bundles_after' => count($frozen),
                    'implausible_dropped' => count($capResult['implausible']),
                    'detect_ids' => count($detectIds),
                ];
            } else {
                $frozen = [];
                foreach ($bundles as $bundle) {
                    $frozen[] = $this->freezeBundle($bundle, $sig);
                }
                $routes[$key] = ['b' => $frozen];
            }

            $bundleTotal += $count;
            if ($count > 1) {
                $multiBundle++;
            }
            if ($count > $largest) {
                $largest = $count;
            }
        }

        return [$routes, [
            'route_keys' => count($routes),
            'multi_bundle_keys' => $multiBundle,
            'largest_bundle_count' => $largest,
            'bundles_total' => $bundleTotal,
            'capped_paths' => $capped,
        ]];
    }

    /**
     * Every routed template id on a key, in bundle order — the full detect id-list the
     * capped entry keeps on `'d'` so detect coverage is never trimmed by the cap.
     *
     * @param Bundle[] $bundles
     * @return string[]
     */
    private function collectDetectIds(array $bundles): array
    {
        $ids = [];
        $seen = [];
        foreach ($bundles as $bundle) {
            foreach ($bundle->templateIds as $id) {
                if (!isset($seen[$id])) {
                    $seen[$id] = true;
                    $ids[] = $id;
                }
            }
        }

        return $ids;
    }

    /**
     * @return array<string,mixed>
     */
    private function freezeBundle(Bundle $bundle, int $sig): array
    {
        $out = [
            's' => $bundle->status ?? 200,
            'bw' => $bundle->bodyWords,
            'hw' => $bundle->headerWords,
            'nf' => $bundle->forbidden,
            'sz' => $this->freezeSize($bundle->size),
            'rx' => $bundle->regexWitness,
            'h' => [], // invented headers are filled by the respond-mode synthesizer
            'pid' => $bundle->product,
            'sev' => $bundle->severity !== '' ? $bundle->severity : 'unknown',
            'sig' => $sig,
            't' => $bundle->templateIds,
        ];

        // Carry header-region forbidden only when present (keeps the artifact lean).
        if ($bundle->headerForbidden !== []) {
            $out['hf'] = $bundle->headerForbidden;
        }

        // Typed-header requirements (canonical name → substrings for that header's value).
        if ($bundle->typedHeader !== []) {
            $out['th'] = $bundle->typedHeader;
        }

        // Whole-body-exclusive flag: an anchored body regex or a size constraint owns the
        // whole body, so the synthesizer must not append other content when serving it.
        if ($bundle->wholeBodyExclusive) {
            $out['x'] = true;
        }

        return $out;
    }

    /**
     * @param array{op:string,n:int}|null $size
     * @return array<string,int>|null
     */
    private function freezeSize($size): ?array
    {
        if ($size === null) {
            return null;
        }

        return [$size['op'] => $size['n']];
    }

    /**
     * @param array<string,mixed> $meta
     * @param array<string,mixed> $stats
     * @param array<string,mixed> $routeStats
     * @return array<string,mixed>
     */
    private function manifest(array $meta, array $stats, array $routeStats, int $templateCount): array
    {
        $capped = $routeStats['capped_paths'] ?? [];

        return [
            'schema' => 1,
            'source' => 'projectdiscovery/nuclei-templates',
            'license' => 'MIT (c) 2025 ProjectDiscovery, Inc.',
            'upstream_tag' => (string) ($meta['tag'] ?? 'unknown'),
            'upstream_sha' => (string) ($meta['sha'] ?? 'unknown'),
            'built_at' => (string) ($meta['built_at'] ?? gmdate('c')),
            'templates_seen' => $stats['total'],
            'templates_in' => $stats['in'],
            'templates_indexed' => $templateCount,
            'route_keys' => $routeStats['route_keys'],
            'multi_bundle_keys' => $routeStats['multi_bundle_keys'],
            'largest_bundle_count' => $routeStats['largest_bundle_count'],
            'persona_cap' => [
                'n' => PersonaCap::N,
                'capped_path_count' => count($capped),
                'capped_paths' => $capped,
                'deferred_cross_path_coherence' => 'Phase 3.5: persona is picked independently per path'
                    . ' (seed % sum(w)), so a single scan can get e.g. WordPress at / and Jenkins at'
                    . ' /index.php. Residual tell, not blocking; fix by choosing one product family per'
                    . ' attacker from a global weighted table.',
            ],
        ];
    }

    /**
     * @param array<string,int> $bag
     */
    private function bump(array &$bag, string $key): void
    {
        $bag[$key] = ($bag[$key] ?? 0) + 1;
    }
}
