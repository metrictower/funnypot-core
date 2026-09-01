<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;

/**
 * FP-0233 — the decoy OpenAPI/Swagger + sitemap surface graph (finite core).
 *
 * The whole point of the graph is that it is CONNECTED and CLOSED: robots.txt → sitemap.xml → every
 * literal endpoint + every doc; the OpenAPI/Swagger docs + the OIDC discovery document advertise the
 * SAME literal endpoints; and every advertised path resolves to an inert, size-capped, non-reflecting
 * decoy. An agent that enumerates the docs and probes the paths must never see docs-say-yes /
 * server-says-no (the "partial-tree tell" the ticket forbids).
 *
 * The route-integrity linter CANNOT see the `<loc>` / absolute-URL / `{{…}}` advertisements (it skips
 * scheme-prefixed URLs and directive spans — ManifestBuilder::classifyTarget), so THIS test is the
 * real enforcement that every advertised path resolves. It fetches each surface, extracts every
 * advertised path (resolving each against its declared server base), and asserts the honeypot serves
 * an inert decoy at it across the persona-rotation seed space.
 */
final class SurfaceGraphRoutingTest extends TestCase
{
    /** The 13 structurally distinct surface-graph archetypes, one representative path each (FP-0174). */
    private const ARCHETYPES = [
        'sitemap'    => '/sitemap.xml',
        'robots'     => '/robots.txt',
        'oidc'       => '/.well-known/openid-configuration',
        'jwks'       => '/.well-known/jwks.json',
        'api-root'   => '/api',
        'collection' => '/api/v1/users',
        'detail'     => '/api/v1/status',
        'admin-html' => '/admin',
        'metrics'    => '/metrics',
        'health'     => '/status',
        'webhooks'   => '/webhooks',
        'graphql'    => '/graphql',
        'auth'       => '/auth',
    ];

    /**
     * The Part-B `common_endpoints` wordlist roots the agents carry hardcoded — enumeration must walk
     * straight in (each resolves to an inert decoy). Every one is a compiled new_page literal.
     */
    private const WORDLIST_ROOTS = [
        '/api', '/api/v1', '/v1', '/admin', '/users', '/auth', '/auth/login', '/auth/token',
        '/webhooks', '/metrics', '/status', '/debug', '/graphql',
    ];

    private function inverter(): Honeypot
    {
        return $this->seededInverter('fixed');
    }

    private function seededInverter(string $seed): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic'
        ));
    }

    /** Strip scheme+authority (and any query/fragment) from a URL, leaving the root-absolute path. */
    private static function toPath(string $url): string
    {
        $url = trim($url);
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $url) === 1) {
            $path = (string) parse_url($url, PHP_URL_PATH);
            $url = $path === '' ? '/' : $path;
        }
        $q = strpos($url, '?');
        if ($q !== false) {
            $url = substr($url, 0, $q);
        }

        return $url;
    }

    /** Fetch a surface body at the fixed seed (each source below is a deterministic single winner). */
    private function body(string $path): string
    {
        $r = $this->inverter()->respond(new RequestContext('GET', $path));
        self::assertNotNull($r, "{$path} must serve a fake");

        return $r->body;
    }

    /**
     * Every path advertised by the connected graph must resolve to an inert decoy — THE
     * no-partial-tree-tell gate. Extract the advertised path set from every surface, then sweep the
     * persona-rotation seed space and assert each path serves a non-null, inert (200/401), fully
     * rendered (no residual `{{`) response carrying a Content-Type.
     */
    public function test_every_advertised_path_resolves_to_inert_decoy(): void
    {
        $advertised = $this->collectAdvertisedPaths();

        // A meaningful surface: the graph advertises dozens of literals, not a handful.
        self::assertGreaterThan(25, count($advertised), 'the surface graph must advertise a large endpoint set');

        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed);
            foreach ($advertised as $path) {
                $resp = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "seed {$seed}: advertised path {$path} must resolve to a decoy (no partial-tree tell)");
                self::assertContains($resp->status, [200, 401], "seed {$seed}: {$path} must be an inert 200/401");
                self::assertArrayHasKey('Content-Type', $resp->headers, "seed {$seed}: {$path} must carry a Content-Type");
                self::assertStringNotContainsString('{{', $resp->body, "seed {$seed}: {$path} must be fully rendered (no residual directive)");
            }
        }
    }

    /**
     * VERB-AWARE no-partial-tree-tell gate. The path sweep above probes GET only, so a documented
     * operation on a non-GET verb (e.g. `POST /auth/token`) could 404 while `GET` of the same path
     * resolves — a verb-scoped tell an agent replaying the doc's own method would hit. Harvest every
     * (method, path) OPERATION the OpenAPI 3.0 / Swagger 2.0 docs declare and probe with that METHOD,
     * asserting each resolves to a non-null inert decoy across the persona-rotation seed space.
     */
    public function test_every_advertised_operation_resolves_by_its_method(): void
    {
        $ops = $this->collectAdvertisedOperations();

        // The docs declare a meaningful multi-verb surface: the GET collection/detail/service
        // operations plus the two POST auth operations (the OpenAPI 3.0 JSON, the YAML mirror and the
        // Swagger 2.0 doc dedup to the same (method, path) keys — one apex host, one operation set).
        self::assertGreaterThan(6, count($ops), 'the docs must declare a multi-verb operation set (GET collections + POST auth)');
        $labels = array_map(static fn (array $o): string => $o[0] . ' ' . $o[1], $ops);
        self::assertContains('POST /auth/token', $labels, 'the OpenAPI docs declare POST /auth/token — it must be harvested and probed');
        self::assertContains('POST /auth/login', $labels, 'the OpenAPI docs declare POST /auth/login — it must be harvested and probed');

        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed);
            foreach ($ops as [$method, $path]) {
                $resp = $inv->respond(new RequestContext($method, $path));
                self::assertNotNull($resp, "seed {$seed}: advertised operation {$method} {$path} must resolve to a decoy (no verb-scoped partial-tree tell)");
                self::assertContains($resp->status, [200, 401], "seed {$seed}: {$method} {$path} must be an inert 200/401");
                self::assertArrayHasKey('Content-Type', $resp->headers, "seed {$seed}: {$method} {$path} must carry a Content-Type");
                self::assertStringNotContainsString('{{', $resp->body, "seed {$seed}: {$method} {$path} must be fully rendered (no residual directive)");
            }
        }
    }

    /**
     * Harvest every (METHOD, path) operation the OpenAPI 3.0 / Swagger 2.0 / OpenAPI-YAML docs
     * declare: for each `paths` entry, each HTTP-verb key under it is one operation, resolved against
     * that doc's server base. Asserts no operation path carries a `{` placeholder (it could never be
     * probed). Deduplicated on "METHOD path".
     *
     * @return array<int,array{0:string,1:string}>
     */
    private function collectAdvertisedOperations(): array
    {
        $verbs = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options', 'trace'];
        $ops = [];
        $addOp = static function (string $method, string $base, string $path) use (&$ops): void {
            $full = self::toPath($base . $path);
            if ($full === '' || $full[0] !== '/') {
                return;
            }
            self::assertStringNotContainsString('{', $full, "advertised operation path '{$full}' carries an unexpanded/parameterized placeholder and would never be probed");
            $ops[strtoupper($method) . ' ' . $full] = [strtoupper($method), $full];
        };

        $harvest = static function (array $paths, string $base) use ($verbs, $addOp): void {
            foreach ($paths as $path => $item) {
                if (!is_array($item)) {
                    continue;
                }
                foreach ($verbs as $verb) {
                    if (isset($item[$verb])) {
                        $addOp($verb, $base, (string) $path);
                    }
                }
            }
        };

        // OpenAPI 3.0 (/swagger.json) — servers[0].url base.
        $oas = json_decode($this->body('/swagger.json'), true);
        self::assertIsArray($oas, 'OpenAPI 3.0 doc must be valid JSON');
        $base3 = self::toPath((string) ($oas['servers'][0]['url'] ?? ''));
        $base3 = $base3 === '/' ? '' : rtrim($base3, '/');
        $harvest((array) ($oas['paths'] ?? []), $base3);

        // OpenAPI YAML (/openapi.yaml) — servers[0].url base.
        $yaml = Yaml::parse($this->body('/openapi.yaml'));
        self::assertIsArray($yaml, 'OpenAPI YAML doc must parse');
        $baseY = self::toPath((string) ($yaml['servers'][0]['url'] ?? ''));
        $baseY = $baseY === '/' ? '' : rtrim($baseY, '/');
        $harvest((array) ($yaml['paths'] ?? []), $baseY);

        // Swagger 2.0 (/v2/api-docs) — basePath base.
        $sw2 = json_decode($this->body('/v2/api-docs'), true);
        self::assertIsArray($sw2, 'Swagger 2.0 doc must be valid JSON');
        $base2 = rtrim((string) ($sw2['basePath'] ?? ''), '/');
        $harvest((array) ($sw2['paths'] ?? []), $base2);

        return array_values($ops);
    }

    /**
     * @return array<int,string> the deduplicated advertised path set drawn from every surface.
     */
    private function collectAdvertisedPaths(): array
    {
        $paths = [];
        $add = static function (string $p) use (&$paths): void {
            $p = self::toPath($p);
            // A cross-scheme / non-path advertisement (about:blank, mailto:, a bare token) is not a
            // same-host root-absolute path — it is not probed here.
            if ($p === '' || $p[0] !== '/') {
                return;
            }
            // No advertised path may carry an unexpanded `{{…}}` directive or an OpenAPI `{param}`
            // placeholder: such a path would be dropped from the probe set and slip through unchecked
            // (the old harvest silently skipped `{`). This finite decoy surface is all literals, so a
            // `{` here is a real defect — fail loudly rather than skip.
            self::assertStringNotContainsString('{', $p, "advertised path '{$p}' carries an unexpanded/parameterized placeholder and would never be probed");
            $paths[$p] = true;
        };

        // sitemap.xml — every <loc>.
        if (preg_match_all('#<loc>\s*([^<\s]+)\s*</loc>#i', $this->body('/sitemap.xml'), $m)) {
            foreach ($m[1] as $loc) {
                $add($loc);
            }
        }

        // robots.txt — every Disallow: path and the Sitemap: URL.
        foreach (explode("\n", $this->body('/robots.txt')) as $line) {
            if (preg_match('/^\s*Disallow:\s*(\S+)/i', $line, $mm)) {
                $add($mm[1]);
            } elseif (preg_match('/^\s*Sitemap:\s*(\S+)/i', $line, $mm)) {
                $add($mm[1]);
            }
        }

        // OIDC discovery — every *_endpoint + jwks_uri.
        $oidc = json_decode($this->body('/.well-known/openid-configuration'), true);
        self::assertIsArray($oidc, 'OIDC discovery must be valid JSON');
        foreach ($oidc as $k => $v) {
            if (is_string($v) && (substr((string) $k, -9) === '_endpoint' || $k === 'jwks_uri')) {
                $add($v);
            }
        }

        // OpenAPI 3.0 (/swagger.json) — server base path + every paths key.
        $oas = json_decode($this->body('/swagger.json'), true);
        self::assertIsArray($oas, 'OpenAPI 3.0 doc must be valid JSON');
        $base3 = self::toPath((string) ($oas['servers'][0]['url'] ?? ''));
        $base3 = $base3 === '/' ? '' : rtrim($base3, '/');
        foreach (array_keys((array) ($oas['paths'] ?? [])) as $p) {
            $add($base3 . $p);
        }

        // Swagger 2.0 (/v2/api-docs) — basePath + every paths key.
        $sw2 = json_decode($this->body('/v2/api-docs'), true);
        self::assertIsArray($sw2, 'Swagger 2.0 doc must be valid JSON');
        $base2 = rtrim((string) ($sw2['basePath'] ?? ''), '/');
        foreach (array_keys((array) ($sw2['paths'] ?? [])) as $p) {
            $add($base2 . $p);
        }

        // OpenAPI YAML (/openapi.yaml) — server base path + every paths key.
        $yaml = Yaml::parse($this->body('/openapi.yaml'));
        self::assertIsArray($yaml, 'OpenAPI YAML doc must parse');
        $baseY = self::toPath((string) ($yaml['servers'][0]['url'] ?? ''));
        $baseY = $baseY === '/' ? '' : rtrim($baseY, '/');
        foreach (array_keys((array) ($yaml['paths'] ?? [])) as $p) {
            $add($baseY . $p);
        }

        // /api/v2 index — its documentation + endpoints map.
        $v2 = json_decode($this->body('/api/v2'), true);
        self::assertIsArray($v2, '/api/v2 index must be valid JSON');
        if (isset($v2['documentation'])) {
            $add((string) $v2['documentation']);
        }
        foreach ((array) ($v2['endpoints'] ?? []) as $u) {
            $add((string) $u);
        }

        // problem+json `type` URIs — a same-host `type` that 404s is a dangling advertisement. The
        // RFC 7807 default `about:blank` is not a same-host path, so $add drops it (nothing to probe).
        foreach (['/auth', '/auth/token'] as $authPath) {
            $prob = json_decode($this->body($authPath), true);
            if (is_array($prob) && isset($prob['type']) && is_string($prob['type'])) {
                $add($prob['type']);
            }
        }

        // .well-known/ai-plugin.json — the manifest URLs a crawler follows (the OpenAPI doc, and the
        // optional logo/legal links). Every same-host one must resolve, or the manifest advertises a
        // hole.
        $plugin = json_decode($this->body('/.well-known/ai-plugin.json'), true);
        self::assertIsArray($plugin, 'ai-plugin manifest must be valid JSON');
        if (isset($plugin['api']['url']) && is_string($plugin['api']['url'])) {
            $add($plugin['api']['url']);
        }
        foreach (['logo_url', 'legal_info_url'] as $optional) {
            if (isset($plugin[$optional]) && is_string($plugin[$optional])) {
                $add($plugin[$optional]);
            }
        }

        return array_keys($paths);
    }

    /**
     * The graph is a connected spine: robots names the sitemap, the sitemap lists the doc URLs, the
     * OIDC discovery points at the JWKS the honeypot also serves, and the docs share one host identity.
     */
    public function test_surface_graph_is_cross_linked(): void
    {
        $robots = $this->body('/robots.txt');
        self::assertMatchesRegularExpression('#^\s*Sitemap:\s*https?://\S+/sitemap\.xml#im', $robots, 'robots.txt must name the sitemap');

        $sitemap = $this->body('/sitemap.xml');
        foreach (['/openapi.json', '/swagger.json', '/v2/api-docs', '/.well-known/openid-configuration', '/.well-known/jwks.json'] as $doc) {
            self::assertStringContainsString($doc . '</loc>', $sitemap, "sitemap must list the doc/well-known URL {$doc}");
        }

        // The OIDC jwks_uri points at a JWKS the honeypot actually serves (the link is not dangling).
        $oidc = json_decode($this->body('/.well-known/openid-configuration'), true);
        self::assertIsArray($oidc);
        $jwksPath = self::toPath((string) ($oidc['jwks_uri'] ?? ''));
        $jwks = $this->inverter()->respond(new RequestContext('GET', $jwksPath));
        self::assertNotNull($jwks, 'the OIDC jwks_uri must resolve');
        self::assertStringContainsString('"kty"', $jwks->body, 'the jwks_uri must serve a key set');

        // One host identity: every advertised endpoint URL uses the SAME apex host (no stray
        // subdomain). Scan the sitemap's <loc> URLs and the JSON doc URL values — NOT the sitemap's
        // xmlns schema namespace, which is a fixed www.sitemaps.org URI, not a host advertisement.
        $urls = '';
        if (preg_match_all('#<loc>\s*([^<\s]+)\s*</loc>#i', $sitemap, $lm)) {
            $urls .= implode("\n", $lm[1]) . "\n";
        }
        $urls .= $this->body('/api/v2') . $this->body('/.well-known/openid-configuration');
        $hosts = [];
        if (preg_match_all('#https?://([^/<"\s]+)#i', $urls, $hm)) {
            foreach ($hm[1] as $h) {
                $hosts[$h] = true;
            }
        }
        self::assertCount(1, $hosts, 'the surface must present one host identity, got: ' . implode(', ', array_keys($hosts)));
    }

    /**
     * No archetype reflects a request byte: request each representative path with a marker in the
     * query, raw body and a header, and assert the marker never lands in the served body. These are
     * fully persona-seeded decoys, so they serve from any origin without a reflecting-decoy gate.
     */
    public function test_advertised_paths_do_not_reflect_request_bytes(): void
    {
        $marker = 'ZZreflectMARKER9137';
        $inv = $this->inverter();
        foreach (self::ARCHETYPES as $label => $path) {
            $r = $inv->respond(new RequestContext(
                'GET',
                $path,
                'q=' . $marker,
                ['X-Probe' => $marker],
                $marker
            ));
            self::assertNotNull($r, "{$label} ({$path}) must serve");
            self::assertStringNotContainsString($marker, $r->body, "{$label} ({$path}) must not reflect the request marker");
        }
    }

    /**
     * Every surface body stays under the hard cap (Config::$maxBodyBytes = 65536). A larger body is
     * refused at synth → respond null → a hole in the tree (a partial-tree tell). Sweep seeds.
     */
    public function test_surface_bodies_are_size_capped(): void
    {
        $cap = 65536;
        $paths = array_merge(array_values(self::ARCHETYPES), [
            '/openapi.json', '/openapi.yaml', '/swagger.json', '/v2/api-docs', '/api/v2', '/swagger-ui.html',
        ]);
        for ($seed = 0; $seed <= 20; $seed++) {
            $inv = $this->seededInverter((string) $seed);
            foreach ($paths as $path) {
                $r = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($r, "seed {$seed}: {$path} must serve");
                self::assertLessThan($cap, strlen($r->body), "seed {$seed}: {$path} body must stay under the {$cap}-byte cap");
            }
        }
    }

    /**
     * FP-0174 / katana anti-dedup: because bodies are persona-seeded (NOT path-seeded), variety must
     * come from distinct SHAPES, not distinct paths. Assert the number of structurally distinct
     * archetype bodies equals the archetype count — no two archetypes collapse to one crawl node.
     */
    public function test_surface_is_structurally_diverse(): void
    {
        $inv = $this->inverter();
        $skeletons = [];
        foreach (self::ARCHETYPES as $label => $path) {
            $r = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($r, "{$label} ({$path}) must serve");
            $skeletons[$this->skeleton($r->headers['Content-Type'] ?? '', $r->body)] = true;
        }
        self::assertCount(count(self::ARCHETYPES), $skeletons, 'each archetype must be structurally distinct (katana would dedup collisions)');
    }

    /**
     * A structural skeleton independent of the seeded VALUES: for JSON, the recursively-collected,
     * sorted set of object keys; otherwise the Content-Type plus a value-stripped first line.
     */
    private function skeleton(string $contentType, string $body): string
    {
        $decoded = json_decode($body, true);
        if (is_array($decoded)) {
            $keys = [];
            $walk = static function ($node) use (&$walk, &$keys): void {
                if (!is_array($node)) {
                    return;
                }
                foreach ($node as $k => $v) {
                    if (is_string($k) && $k !== '_comment') {
                        $keys[$k] = true;
                    }
                    $walk($v);
                }
            };
            $walk($decoded);
            $names = array_keys($keys);
            sort($names);

            return 'json:' . implode(',', $names);
        }
        $firstLine = strtok($body, "\n");
        $firstLine = preg_replace('/[0-9a-f]{6,}|[0-9]+/i', '#', (string) $firstLine);

        return 'raw:' . $contentType . '|' . substr((string) $firstLine, 0, 60);
    }

    /**
     * Every Part-B `common_endpoints` wordlist root resolves to an inert decoy across the seed space —
     * enumeration walks straight into the tarpit rather than bottoming out on a 404.
     */
    public function test_wordlist_roots_all_resolve(): void
    {
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed);
            foreach (self::WORDLIST_ROOTS as $root) {
                $r = $inv->respond(new RequestContext('GET', $root));
                self::assertNotNull($r, "seed {$seed}: wordlist root {$root} must resolve to a decoy");
                self::assertContains($r->status, [200, 401], "seed {$seed}: {$root} must be an inert 200/401");
                self::assertStringNotContainsString('{{', $r->body, "seed {$seed}: {$root} must be fully rendered");
            }
        }
    }
}
