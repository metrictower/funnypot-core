<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\SurfaceGraph;
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

    /** The deploy materials the FP-0278 coherence sweep varies the IDENTITY seed over. */
    private const DEPLOY_MATERIALS = [
        '', 'funnypot', 'fp-0278-a', 'fp-0278-b', 'fp-0278-c', 'fp-0278-d', 'fp-0278-e', 'fp-0278-f',
        'fp-0278-g', 'fp-0278-h', 'fp-0278-i', 'fp-0278-j', 'fp-0278-k', 'fp-0278-l', 'fp-0278-m',
        'fp-0278-n', 'fp-0278-o', 'fp-0278-p', 'fp-0278-q', 'fp-0278-r', 'fp-0278-s', 'fp-0278-t',
        'fp-0278-u', 'fp-0278-v', 'fp-0278-w', 'fp-0278-x', 'fp-0278-y', 'fp-0278-z',
    ];

    private function inverter(): Honeypot
    {
        return $this->seededInverter('fixed');
    }

    /**
     * The render-seed axis (FP-0233): the seed is Config ctor arg 4, the per-REQUEST persona-seed
     * source (Config.php $personaSeed). This exercises PersonaSelector::pick at co-tenanted keys — the
     * FP-0233 guarantee — but does NOT vary the deploy-seeded surface graph (deploySeed/seedSalt unset
     * ⇒ deploySeedMaterial() is '' every iteration), so it is the WITHIN-deploy axis for this ticket.
     */
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

    /**
     * The deploy-seed axis (FP-0278): setting deploySeed + seedSalt varies the IDENTITY seed
     * (Config::deploySeed() → Honeypot → DirectiveRenderer::identitySeed()), which drives the seeded
     * surface graph. This is the axis every coherence assertion below sweeps — the render-seed-only
     * sweep would be VACUOUS for this ticket (the graph is constant along it).
     */
    private function deployInverter(string $material): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            null,
            'coherent',
            'realistic'
        );
        $config->deploySeed = $material;
        $config->seedSalt = 'fp-0278-salt';

        return new Honeypot($store, $config);
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

    /** Fetch a surface body from the given inverter (defaults to the fixed within-deploy inverter). */
    private function body(string $path, ?Honeypot $inv = null): string
    {
        $inv = $inv ?? $this->inverter();
        $r = $inv->respond(new RequestContext('GET', $path));
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

    // === FP-0278: coherence at every sampled DEPLOY seed (the identity-seed axis) ==================

    /** Segment-aware "does $root cover $p" — /status covers /status and /status/x, never /statuses. */
    private static function covers(string $root, string $p): bool
    {
        return $p === $root || strpos($p, $root . '/') === 0;
    }

    /** The sitemap's <loc> paths for one deploy. @return list<string> */
    private function sitemapLocs(Honeypot $inv): array
    {
        $locs = [];
        if (preg_match_all('#<loc>\s*([^<\s]+)\s*</loc>#i', $this->body('/sitemap.xml', $inv), $m)) {
            foreach ($m[1] as $loc) {
                $locs[] = self::toPath($loc);
            }
        }

        return $locs;
    }

    /** The robots Disallow: roots for one deploy. @return list<string> */
    private function disallowRoots(Honeypot $inv): array
    {
        $roots = [];
        foreach (explode("\n", $this->body('/robots.txt', $inv)) as $line) {
            if (preg_match('/^\s*Disallow:\s*(\S+)/i', $line, $mm)) {
                $roots[] = self::toPath($mm[1]);
            }
        }

        return $roots;
    }

    /**
     * Every same-host path a body LINKS for one deploy (397 _links + documentation, 400 hrefs, 345
     * endpoints incl. auth, 395 *_endpoint/jwks_uri). @return list<string>
     */
    private function linkedPaths(Honeypot $inv): array
    {
        $links = [];
        $addLink = static function ($u) use (&$links): void {
            $p = self::toPath((string) $u);
            if ($p !== '' && $p[0] === '/') {
                $links[$p] = true;
            }
        };
        $root = json_decode($this->body('/api', $inv), true);
        self::assertIsArray($root, '/api root index must be valid JSON');
        foreach ((array) ($root['_links'] ?? []) as $u) {
            $addLink($u);
        }
        if (isset($root['documentation'])) {
            $addLink($root['documentation']);
        }
        if (preg_match_all('#href="(/[^"]*)"#i', $this->body('/admin', $inv), $hm)) {
            foreach ($hm[1] as $href) {
                $addLink($href);
            }
        }
        $v2 = json_decode($this->body('/api/v2', $inv), true);
        self::assertIsArray($v2, '/api/v2 index must be valid JSON');
        foreach ((array) ($v2['endpoints'] ?? []) as $u) {
            $addLink($u);
        }
        if (isset($v2['documentation'])) {
            $addLink($v2['documentation']);
        }
        $oidc = json_decode($this->body('/.well-known/openid-configuration', $inv), true);
        self::assertIsArray($oidc, 'OIDC discovery must be valid JSON');
        foreach ((array) $oidc as $k => $v) {
            if (is_string($v) && (substr((string) $k, -9) === '_endpoint' || $k === 'jwks_uri')) {
                $addLink($v);
            }
        }

        return array_keys($links);
    }

    /**
     * The distinct nouns of one $pool that appear as the LAST segment of any path in $paths (pools are
     * disjoint, so a path's slot class is unambiguous). @param list<string> $paths @return list<string>
     */
    private static function nounsIn(array $paths, array $pool): array
    {
        $found = [];
        foreach ($paths as $p) {
            $seg = substr($p, (int) strrpos($p, '/') + 1);
            if (in_array($seg, $pool, true)) {
                $found[$seg] = true;
            }
        }
        $out = array_keys($found);
        sort($out);

        return $out;
    }

    /** The `paths` keys of a JSON OpenAPI/Swagger doc, resolved against $base. @return list<string> */
    private function docPaths(Honeypot $inv, string $path, string $base): array
    {
        $doc = json_decode($this->body($path, $inv), true);
        self::assertIsArray($doc, "{$path} must be valid JSON");
        $out = [];
        foreach (array_keys((array) ($doc['paths'] ?? [])) as $p) {
            $out[] = self::toPath($base . $p);
        }

        return $out;
    }

    /**
     * C1 (deploy axis): every advertised path resolves to an inert decoy at EVERY sampled deploy seed.
     * The render-seed sweep above is vacuous for the seeded graph; THIS sweep varies the identity seed.
     */
    public function test_every_advertised_path_resolves_across_deploy_seeds(): void
    {
        foreach (self::DEPLOY_MATERIALS as $material) {
            $inv = $this->deployInverter($material);
            $advertised = $this->collectAdvertisedPaths($inv);
            self::assertGreaterThan(25, count($advertised), "material '{$material}': the graph must advertise a large endpoint set");
            foreach ($advertised as $path) {
                $resp = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($resp, "material '{$material}': advertised {$path} must resolve (no partial-tree tell)");
                self::assertContains($resp->status, [200, 401], "material '{$material}': {$path} must be an inert 200/401");
                self::assertArrayHasKey('Content-Type', $resp->headers, "material '{$material}': {$path} must carry a Content-Type");
                self::assertStringNotContainsString('{{', $resp->body, "material '{$material}': {$path} must be fully rendered");
            }
        }
    }

    /**
     * C2 (linked ⇒ advertised): every same-host path a body links is a sitemap <loc> or lies under a
     * Disallow root, at every deploy seed. Includes the two plan-review cases as named checks.
     */
    public function test_every_linked_path_is_advertised_across_deploys(): void
    {
        foreach (self::DEPLOY_MATERIALS as $material) {
            $inv = $this->deployInverter($material);
            $locs = $this->sitemapLocs($inv);
            $roots = $this->disallowRoots($inv);
            $linked = $this->linkedPaths($inv);
            self::assertNotEmpty($linked, "material '{$material}': the surfaces must link paths");

            foreach ($linked as $p) {
                $advertised = in_array($p, $locs, true);
                if (!$advertised) {
                    foreach ($roots as $root) {
                        if (self::covers($root, $p)) {
                            $advertised = true;
                            break;
                        }
                    }
                }
                self::assertTrue($advertised, "material '{$material}': linked path {$p} must be advertised (a sitemap loc or under a Disallow root)");
            }

            // Named review cases: /api and /api/v1 always advertised; 345's auth is /auth/login,
            // covered by the always-present Disallow: /auth.
            self::assertContains('/api', $locs, "material '{$material}': /api must be a sitemap loc (SPINE)");
            self::assertContains('/api/v1', $locs, "material '{$material}': /api/v1 must be a sitemap loc (SPINE)");
            $v2 = json_decode($this->body('/api/v2', $inv), true);
            self::assertSame('/auth/login', self::toPath((string) ($v2['endpoints']['auth'] ?? '')), "material '{$material}': /api/v2 auth must link /auth/login, not /api/v2/auth/login");
            $authCovered = false;
            foreach ($roots as $root) {
                if (self::covers($root, '/auth/login')) {
                    $authCovered = true;
                }
            }
            self::assertTrue($authCovered, "material '{$material}': /auth/login must be covered by a Disallow root");
        }
    }

    /**
     * C3 (no sitemap/robots contradiction): no sitemap <loc> is covered by a Disallow root, and /api
     * never appears as a Disallow root, at every deploy seed.
     */
    public function test_no_sitemap_robots_contradiction_across_deploys(): void
    {
        foreach (self::DEPLOY_MATERIALS as $material) {
            $inv = $this->deployInverter($material);
            $locs = $this->sitemapLocs($inv);
            $roots = $this->disallowRoots($inv);
            self::assertNotContains('/api', $roots, "material '{$material}': /api must not be Disallow-ed (the sitemap advertises the /api tree)");
            foreach ($locs as $loc) {
                foreach ($roots as $root) {
                    self::assertFalse(self::covers($root, $loc), "material '{$material}': sitemap loc {$loc} must not be covered by Disallow {$root}");
                }
            }
        }
    }

    /**
     * C4 (one noun story, per slot class): the COLLECTION nouns agree across sitemap/330/340/342/341/
     * 345/397/400; the SINGLETON nouns agree across sitemap/330/340/342/341/397 (345 and 400 carry
     * none by design) — at every deploy seed.
     */
    public function test_one_noun_story_per_slot_class_across_deploys(): void
    {
        $col = SurfaceGraph::COLLECTION_NOUNS;
        $det = SurfaceGraph::DETAIL_NOUNS;
        foreach (self::DEPLOY_MATERIALS as $material) {
            $inv = $this->deployInverter($material);
            $locs = $this->sitemapLocs($inv);
            $links = $this->linkedPaths($inv);
            $p330 = $this->docPaths($inv, '/openapi.json', '');
            $p340 = $this->docPaths($inv, '/swagger.json', '');
            $p342Doc = Yaml::parse($this->body('/openapi.yaml', $inv));
            $p342 = array_map([self::class, 'toPath'], array_keys((array) ($p342Doc['paths'] ?? [])));
            $sw2 = json_decode($this->body('/v2/api-docs', $inv), true);
            self::assertIsArray($sw2, 'Swagger 2.0 doc must be valid JSON');
            $base2 = rtrim((string) ($sw2['basePath'] ?? ''), '/');
            $p341 = [];
            foreach (array_keys((array) ($sw2['paths'] ?? [])) as $p) {
                $p341[] = self::toPath($base2 . $p);
            }

            // Collection nouns across all eight advertisers.
            $collectionSets = [
                'sitemap' => self::nounsIn($locs, $col),
                '330' => self::nounsIn($p330, $col),
                '340' => self::nounsIn($p340, $col),
                '342' => self::nounsIn($p342, $col),
                '341' => self::nounsIn($p341, $col),
                'links(397/400/345)' => self::nounsIn($links, $col),
            ];
            $expectCol = $collectionSets['sitemap'];
            self::assertCount(2, $expectCol, "material '{$material}': the sitemap must carry exactly two collection nouns");
            foreach ($collectionSets as $src => $set) {
                self::assertSame($expectCol, $set, "material '{$material}': collection nouns from {$src} must match the sitemap");
            }

            // Singleton nouns across sitemap/330/340/342/341/397 only.
            $links397 = [];
            $root = json_decode($this->body('/api', $inv), true);
            foreach ((array) ($root['_links'] ?? []) as $u) {
                $links397[] = self::toPath((string) $u);
            }
            $singletonSets = [
                'sitemap' => self::nounsIn($locs, $det),
                '330' => self::nounsIn($p330, $det),
                '340' => self::nounsIn($p340, $det),
                '342' => self::nounsIn($p342, $det),
                '341' => self::nounsIn($p341, $det),
                '397' => self::nounsIn($links397, $det),
            ];
            $expectDet = $singletonSets['sitemap'];
            self::assertCount(2, $expectDet, "material '{$material}': the sitemap must carry exactly two singleton nouns");
            foreach ($singletonSets as $src => $set) {
                self::assertSame($expectDet, $set, "material '{$material}': singleton nouns from {$src} must match the sitemap");
            }
        }
    }

    /** C5 (ops paths robots-only): no NEVER_IN_SITEMAP path ever appears as a <loc>, at every seed. */
    public function test_ops_paths_are_never_sitemapped_across_deploys(): void
    {
        foreach (self::DEPLOY_MATERIALS as $material) {
            $locs = $this->sitemapLocs($this->deployInverter($material));
            foreach (SurfaceGraph::NEVER_IN_SITEMAP as $never) {
                self::assertNotContains($never, $locs, "material '{$material}': ops path {$never} must be robots-only, never sitemapped");
            }
        }
    }

    /**
     * Cross-deploy (domain-stripped): the ORDERED <loc> path list and the ORDERED Disallow list differ
     * between two deploys, and the noun set differs for at least one pair — the load-bearing proof that
     * the graph is de-fingerprinted (the seeded-render gate's G4 alone would pass on the domain).
     */
    public function test_cross_deploy_path_sets_and_nouns_differ(): void
    {
        $a = $this->deployInverter('fp-0278-a');
        $b = $this->deployInverter('fp-0278-b');
        // The sitemap ordering carries the entropy (18!+ permutations), so a specific pair differs.
        self::assertNotSame($this->sitemapLocs($a), $this->sitemapLocs($b), 'the ordered sitemap path list must differ across deploys');

        // The Disallow axis is deliberately small (order of 4 required roots + 0..2 optional ⇒ 96
        // variants — the sitemap is the entropy source), so a SPECIFIC pair can collide; assert the
        // axis is live by requiring >1 distinct ordered Disallow list across the sampled deploys, and
        // that the advertised noun set likewise varies.
        $sitemapOrders = [];
        $disallowOrders = [];
        $nounSets = [];
        foreach (self::DEPLOY_MATERIALS as $material) {
            $inv = $this->deployInverter($material);
            $sitemapOrders[serialize($this->sitemapLocs($inv))] = true;
            $disallowOrders[serialize($this->disallowRoots($inv))] = true;
            $root = json_decode($this->body('/api', $inv), true);
            $nounSets[serialize($root['_links'] ?? [])] = true;
        }
        self::assertGreaterThan(1, count($sitemapOrders), 'the sitemap set/order must vary across deploys');
        self::assertGreaterThan(1, count($disallowOrders), 'the Disallow set/order must vary across deploys');
        self::assertGreaterThan(1, count($nounSets), 'the advertised noun set must vary across deploys');
    }

    /**
     * Within-deploy determinism along the render axis: at ONE deploy material, the sitemap <loc> list
     * is identical across render seeds (the surface graph is a pure function of the deploy seed, not
     * the request). A free companion to the deploy-axis coherence sweep.
     */
    public function test_surface_graph_is_constant_along_the_render_axis(): void
    {
        // seededInverter varies the per-REQUEST persona seed (ctor arg 4), which must NOT move the graph.
        $baseline = null;
        foreach (['0', '1', '7', '4242', 'probe'] as $renderSeed) {
            $locs = $this->sitemapLocs($this->seededInverter($renderSeed));
            if ($baseline === null) {
                $baseline = $locs;
            }
            self::assertSame($baseline, $locs, "render seed {$renderSeed}: the surface graph must be constant along the render axis");
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
     * FP-0274 — the authored POST auth arm. Both POST /auth/login and POST /auth/token must serve the
     * SAME inert 401 problem+json decoy as the GET arm. POST /auth/login previously fell through to a
     * corpus login decoy that returned 200 with a fake `username`/`roles` body (a fake auth SUCCESS the
     * rest of the graph never grants); authoring it in route 406 REPLACES that with the coherent 401.
     * Asserts the FLIP (200→401), a valid problem+json object with status 401 and the required fields,
     * across the seed sweep, and that no request byte (method/path/query/header/body) is reflected.
     */
    public function test_authored_post_auth_serves_the_inert_401_family(): void
    {
        $marker = 'ZZauthMARKER8241';
        for ($seed = 0; $seed <= 30; $seed++) {
            $inv = $this->seededInverter((string) $seed);
            foreach (['/auth/login', '/auth/token'] as $path) {
                foreach (['GET', 'POST'] as $method) {
                    $resp = $inv->respond(new RequestContext(
                        $method,
                        $path,
                        'q=' . $marker,
                        ['X-Probe' => $marker],
                        'body=' . $marker
                    ));
                    self::assertNotNull($resp, "seed {$seed}: {$method} {$path} must resolve");
                    self::assertSame(401, $resp->status, "seed {$seed}: {$method} {$path} must be the authored 401 (not a fake 200 success)");
                    self::assertSame('application/problem+json', $resp->headers['Content-Type'] ?? '', "seed {$seed}: {$method} {$path} must serve problem+json");
                    $doc = json_decode($resp->body, true);
                    self::assertIsArray($doc, "seed {$seed}: {$method} {$path} body must decode to a JSON object");
                    self::assertSame(401, $doc['status'] ?? null, "seed {$seed}: {$method} {$path} problem body status must be 401");
                    self::assertArrayHasKey('title', $doc, "seed {$seed}: {$method} {$path} must carry a problem title");
                    self::assertArrayHasKey('detail', $doc, "seed {$seed}: {$method} {$path} must carry a problem detail");
                    self::assertStringNotContainsString($marker, $resp->body, "seed {$seed}: {$method} {$path} must not reflect a request byte");
                    self::assertStringNotContainsString('{{', $resp->body, "seed {$seed}: {$method} {$path} must be fully rendered");
                }
            }
        }
    }

    /**
     * The POST /auth/login flip is byte-coherent with the token arm: at a fixed seed the authored 401
     * body served for POST /auth/login is identical to POST /auth/token and the GET arm — one decoy
     * family, no fake auth success anywhere on the auth surface.
     */
    public function test_post_auth_login_flips_to_the_shared_401_decoy(): void
    {
        $inv = $this->seededInverter('7');
        $postLogin = $inv->respond(new RequestContext('POST', '/auth/login'));
        self::assertNotNull($postLogin);
        self::assertSame(401, $postLogin->status, 'POST /auth/login must serve the authored 401, not the corpus 200 decoy');
        self::assertStringNotContainsString('"roles"', $postLogin->body, 'the corpus login-success body must no longer win');

        $tokenBody = $inv->respond(new RequestContext('POST', '/auth/token'))->body;
        $getBody = $inv->respond(new RequestContext('GET', '/auth/login'))->body;
        self::assertSame($tokenBody, $postLogin->body, 'POST /auth/login and POST /auth/token must share one authored 401 decoy');
        self::assertSame($getBody, $postLogin->body, 'the POST and GET auth arms must serve one 401 decoy family');
    }

    /**
     * The advertised failure outcome is coherent: every OpenAPI/Swagger/YAML mirror that declares
     * POST /auth/login now advertises a 401 response for it (the authored server answer), so an agent
     * reading the doc and replaying the operation is not told success-only for an endpoint that 401s.
     */
    public function test_openapi_docs_advertise_401_for_post_auth_login(): void
    {
        $checked = 0;
        $docs = [
            ['/openapi.json', 'json'],
            ['/swagger.json', 'json'],
            ['/openapi.yaml', 'yaml'],
        ];
        foreach ($docs as [$path, $kind]) {
            $doc = $kind === 'yaml' ? Yaml::parse($this->body($path)) : json_decode($this->body($path), true);
            self::assertIsArray($doc, "{$path} must parse");
            $op = $doc['paths']['/auth/login']['post'] ?? null;
            if ($op === null) {
                continue; // this mirror does not carry the operation
            }
            self::assertArrayHasKey('401', (array) ($op['responses'] ?? []), "{$path}: POST /auth/login must advertise a 401 response");
            $checked++;
        }
        self::assertGreaterThanOrEqual(2, $checked, 'at least the OpenAPI 3.0 JSON + YAML mirrors must declare POST /auth/login');
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
    private function collectAdvertisedPaths(?Honeypot $inv = null): array
    {
        $inv = $inv ?? $this->inverter();
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
        if (preg_match_all('#<loc>\s*([^<\s]+)\s*</loc>#i', $this->body('/sitemap.xml', $inv), $m)) {
            foreach ($m[1] as $loc) {
                $add($loc);
            }
        }

        // robots.txt — every Disallow: path and the Sitemap: URL.
        foreach (explode("\n", $this->body('/robots.txt', $inv)) as $line) {
            if (preg_match('/^\s*Disallow:\s*(\S+)/i', $line, $mm)) {
                $add($mm[1]);
            } elseif (preg_match('/^\s*Sitemap:\s*(\S+)/i', $line, $mm)) {
                $add($mm[1]);
            }
        }

        // OIDC discovery — every *_endpoint + jwks_uri.
        $oidc = json_decode($this->body('/.well-known/openid-configuration', $inv), true);
        self::assertIsArray($oidc, 'OIDC discovery must be valid JSON');
        foreach ($oidc as $k => $v) {
            if (is_string($v) && (substr((string) $k, -9) === '_endpoint' || $k === 'jwks_uri')) {
                $add($v);
            }
        }

        // OpenAPI 3.0 (/swagger.json) — server base path + every paths key.
        $oas = json_decode($this->body('/swagger.json', $inv), true);
        self::assertIsArray($oas, 'OpenAPI 3.0 doc must be valid JSON');
        $base3 = self::toPath((string) ($oas['servers'][0]['url'] ?? ''));
        $base3 = $base3 === '/' ? '' : rtrim($base3, '/');
        foreach (array_keys((array) ($oas['paths'] ?? [])) as $p) {
            $add($base3 . $p);
        }

        // Swagger 2.0 (/v2/api-docs) — basePath + every paths key.
        $sw2 = json_decode($this->body('/v2/api-docs', $inv), true);
        self::assertIsArray($sw2, 'Swagger 2.0 doc must be valid JSON');
        $base2 = rtrim((string) ($sw2['basePath'] ?? ''), '/');
        foreach (array_keys((array) ($sw2['paths'] ?? [])) as $p) {
            $add($base2 . $p);
        }

        // OpenAPI YAML (/openapi.yaml) — server base path + every paths key.
        $yaml = Yaml::parse($this->body('/openapi.yaml', $inv));
        self::assertIsArray($yaml, 'OpenAPI YAML doc must parse');
        $baseY = self::toPath((string) ($yaml['servers'][0]['url'] ?? ''));
        $baseY = $baseY === '/' ? '' : rtrim($baseY, '/');
        foreach (array_keys((array) ($yaml['paths'] ?? [])) as $p) {
            $add($baseY . $p);
        }

        // /api/v2 index — its documentation + endpoints map.
        $v2 = json_decode($this->body('/api/v2', $inv), true);
        self::assertIsArray($v2, '/api/v2 index must be valid JSON');
        if (isset($v2['documentation'])) {
            $add((string) $v2['documentation']);
        }
        foreach ((array) ($v2['endpoints'] ?? []) as $u) {
            $add((string) $u);
        }

        // FP-0278: the API root index (397) — every _links value + documentation. A seeded noun link
        // here that were not advertised would be a linked-but-unadvertised tell (C2).
        $root = json_decode($this->body('/api', $inv), true);
        self::assertIsArray($root, '/api root index must be valid JSON');
        if (isset($root['documentation'])) {
            $add((string) $root['documentation']);
        }
        foreach ((array) ($root['_links'] ?? []) as $u) {
            $add((string) $u);
        }

        // FP-0278: the admin dashboard (400) — every root-absolute href.
        if (preg_match_all('#href="(/[^"]*)"#i', $this->body('/admin', $inv), $hm)) {
            foreach ($hm[1] as $href) {
                $add($href);
            }
        }

        // problem+json `type` URIs — a same-host `type` that 404s is a dangling advertisement. The
        // RFC 7807 default `about:blank` is not a same-host path, so $add drops it (nothing to probe).
        foreach (['/auth', '/auth/token'] as $authPath) {
            $prob = json_decode($this->body($authPath, $inv), true);
            if (is_array($prob) && isset($prob['type']) && is_string($prob['type'])) {
                $add($prob['type']);
            }
        }

        // .well-known/ai-plugin.json — the manifest URLs a crawler follows (the OpenAPI doc, and the
        // optional logo/legal links). Every same-host one must resolve, or the manifest advertises a
        // hole.
        $plugin = json_decode($this->body('/.well-known/ai-plugin.json', $inv), true);
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
