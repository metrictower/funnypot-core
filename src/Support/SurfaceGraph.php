<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

/**
 * The single source of truth for the FP-0233 decoy surface graph, de-fingerprinted per deploy
 * (FP-0278). The graph's endpoint SET, ORDER and resource NOUNS were a fleet constant — a
 * cross-deploy correlation tell — so this class derives them as a pure function of the deploy
 * identity seed (via the FP-0276 SubSeed primitive, namespace SubSeed::NS_SURFACE) while keeping the
 * graph internally COHERENT: whatever a deploy advertises is exactly what it serves, and every
 * cross-linked path stays advertised at every seed (the SPINE / ROBOTS_REQUIRED invariants below).
 *
 * DETERMINISM. Every derivation is `SubSeed::index/subset/permute($seed, NS_SURFACE, FIELD)` over the
 * constants here — no clock, CSPRNG, request byte or the 64-bit-only child seed ever enters, so within
 * a deploy the graph is byte-stable and across deploys it varies. The seed handed in is the deploy
 * IDENTITY seed (DirectiveRenderer::identitySeed()), the same seed {{persona.*}} rides.
 *
 * COHERENCE (mechanically pinned by tests/SurfaceGraphRoutingTest at every sampled deploy seed):
 *   - SPINE paths are advertised in the sitemap at EVERY seed (they are linked by 397/341/400/345 or
 *     are the doc/well-known roots), so a link can never point at an un-advertised path.
 *   - ROBOTS_REQUIRED roots (order-seeded only) are in robots.txt at EVERY seed — they cover the
 *     /auth, /webhooks, /metrics, /status links the other surfaces carry.
 *   - The seeded subset/order is drawn only from items nothing links at every seed (optional docs, the
 *     /v1 alias, /graphql, /debug), so seeding one out can never dangle a link.
 *   - NEVER_IN_SITEMAP ops paths are robots-only (a real site never sitemaps /metrics or /debug).
 *
 * The collection/detail NOUN pools are compiled as a fleet-identical SUPERSET (allCandidatePaths()):
 * every noun variant resolves to an inert decoy, and a deploy merely ADVERTISES its seeded subset, so
 * a prober guessing an un-advertised noun still lands on a coherent 200 (never an advertised-but-404
 * or a fingerprintable partial tree). collectionPaths()/detailPaths() pin the 398/399 `paths:` lists.
 *
 * PHP 7.3-safe: array_merge()/array_slice() and SubSeed only.
 */
final class SurfaceGraph
{
    /** The four seeded noun slots: two collection nouns (398 archetype), two singleton nouns (399). */
    public const SLOTS = ['c1', 'c2', 'd1', 'd2'];

    /**
     * Collection nouns (the 398 REST-collection archetype). ALL verified corpus-unowned under
     * /api/v1, /api/v2, / and /admin, so every compiled variant is surface-owned at weight 100000
     * (no merge-routes w=8 demotion). health/info/version/settings/profile are corpus-owned and
     * excluded by construction.
     */
    public const COLLECTION_NOUNS = ['users', 'orders', 'customers', 'accounts', 'invoices', 'products', 'members', 'clients', 'projects', 'subscriptions', 'payments', 'tickets'];

    /**
     * Singleton nouns (the 399 REST-detail archetype). status/config are today's; the other six are
     * grep-verified corpus-unowned under /api/v1. Disjoint from COLLECTION_NOUNS so a noun's slot
     * class is unambiguous.
     */
    public const DETAIL_NOUNS = ['status', 'config', 'environment', 'runtime', 'release', 'build', 'capabilities', 'limits'];

    /**
     * Sitemap spine — ALWAYS advertised. /api and /api/v1 are here (not seedable) because 397 (_links
     * self=/api/v1), 341 (basePath /api/v1) and 400 (nav /api) link them at every seed; the doc and
     * well-known roots are linked by the sitemap cross-link contract itself.
     */
    public const SPINE = ['/openapi.json', '/swagger.json', '/v2/api-docs', '/api/v2', '/.well-known/openid-configuration', '/.well-known/jwks.json', '/api', '/api/v1'];

    /** Optional doc aliases nothing links at every seed — a seeded subset of size 3..6 is advertised. */
    public const OPTIONAL_DOCS = ['/openapi.yaml', '/v3/api-docs', '/api-docs', '/swagger-ui.html', '/.well-known/security.txt', '/.well-known/ai-plugin.json'];

    /** The one API-root alias nothing links — seeded in/out (0..1); stays compiled in 397 regardless. */
    public const OPTIONAL_ROOT = '/v1';

    /** robots: the fixed first Disallow line (also pinned by NewPageRoutingTest). */
    public const ROBOTS_FIXED = '/admin';

    /** robots roots linked from other surfaces (395/397/400/docs) — order-seeded only, never dropped. */
    public const ROBOTS_REQUIRED = ['/auth', '/webhooks', '/metrics', '/status'];

    /** robots roots nothing links — a seeded subset of size 0..2 is advertised. */
    public const ROBOTS_OPTIONAL = ['/graphql', '/debug'];

    /** Ops paths a real site never sitemaps (the "unreal composition" tell) — robots-only. */
    public const NEVER_IN_SITEMAP = ['/metrics', '/status', '/debug', '/auth/token'];

    private function __construct()
    {
    }

    /**
     * The deploy's four seeded nouns: two distinct collection nouns (c1, c2) and two distinct
     * singleton nouns (d1, d2). A pure function of the identity seed.
     *
     * @return array{c1:string,c2:string,d1:string,d2:string}
     */
    public static function nouns(int $seed): array
    {
        $collection = SubSeed::subset(self::COLLECTION_NOUNS, 2, $seed, SubSeed::NS_SURFACE, 'nouns|collection');
        $detail = SubSeed::subset(self::DETAIL_NOUNS, 2, $seed, SubSeed::NS_SURFACE, 'nouns|detail');

        return ['c1' => $collection[0], 'c2' => $collection[1], 'd1' => $detail[0], 'd2' => $detail[1]];
    }

    /** One seeded noun by slot; '' for a slot not in SLOTS (the fail-safe the compile lint rejects first). */
    public static function noun(int $seed, string $slot): string
    {
        $nouns = self::nouns($seed);

        return $nouns[$slot] ?? '';
    }

    /**
     * The deploy's ordered sitemap path list (root-absolute): the SPINE, a seeded 3..6 subset of the
     * optional docs, the /v1 alias on a coin flip, and the seeded noun paths — all permuted. The
     * 18!+ ordered permutation is the entropy source; size is 18..22 (vs 33 fixed fleet-wide).
     *
     * @return list<string>
     */
    public static function sitemapPaths(int $seed): array
    {
        $nouns = self::nouns($seed);
        $members = self::SPINE;

        // Optional docs: a seeded subset of size 3..6 (lo + index(hi-lo+1) range sugar, inlined).
        $optionalCount = 3 + SubSeed::index($seed, SubSeed::NS_SURFACE, 'sitemap|optional-k', 4);
        $members = array_merge($members, SubSeed::subset(self::OPTIONAL_DOCS, $optionalCount, $seed, SubSeed::NS_SURFACE, 'sitemap|optional'));

        // The /v1 alias — a single membership coin flip (nothing links it, so it is safe to seed).
        if (SubSeed::index($seed, SubSeed::NS_SURFACE, 'sitemap|v1', 2) === 1) {
            $members[] = self::OPTIONAL_ROOT;
        }

        // The seeded noun paths (the noun story the docs/robots/nav all agree on).
        $members[] = '/api/v1/' . $nouns['c1'];
        $members[] = '/api/v1/' . $nouns['c2'];
        $members[] = '/api/v1/' . $nouns['d1'];
        $members[] = '/api/v1/' . $nouns['d2'];
        $members[] = '/api/v2/' . $nouns['c1'];
        $members[] = '/api/v2/' . $nouns['c2'];
        $members[] = '/' . $nouns['c1'];

        return SubSeed::permute($members, $seed, SubSeed::NS_SURFACE, 'sitemap|order');
    }

    /**
     * The deploy's `<url><loc>…</loc></url>` block, newline-joined (no trailing newline). DOMAIN is
     * the caller's already-resolved persona company.domain, so the sitemap host matches the rest of
     * the page. Contains no `{{` and no digit run.
     */
    public static function sitemapBlock(int $seed, string $domain): string
    {
        $lines = [];
        foreach (self::sitemapPaths($seed) as $path) {
            $lines[] = '<url><loc>https://' . $domain . $path . '</loc></url>';
        }

        return implode("\n", $lines);
    }

    /**
     * The deploy's ordered Disallow path list: /admin first, then the required roots in seeded order,
     * then a seeded 0..2 subset of the optional roots.
     *
     * @return list<string>
     */
    public static function disallowPaths(int $seed): array
    {
        $required = SubSeed::permute(self::ROBOTS_REQUIRED, $seed, SubSeed::NS_SURFACE, 'robots|order');
        $optionalCount = SubSeed::index($seed, SubSeed::NS_SURFACE, 'robots|optional-k', 3); // 0..2
        $optional = SubSeed::subset(self::ROBOTS_OPTIONAL, $optionalCount, $seed, SubSeed::NS_SURFACE, 'robots|optional');

        return array_merge([self::ROBOTS_FIXED], $required, $optional);
    }

    /** The deploy's `Disallow: …` block, newline-joined (no trailing newline), always /admin first. */
    public static function disallowBlock(int $seed): string
    {
        $lines = [];
        foreach (self::disallowPaths($seed) as $path) {
            $lines[] = 'Disallow: ' . $path;
        }

        return implode("\n", $lines);
    }

    /**
     * The compile-time SUPERSET: every noun path any seed can advertise (collection + detail). Every
     * entry must be a surface-owned compiled key so an advertised subset never 404s.
     *
     * @return list<string>
     */
    public static function allCandidatePaths(): array
    {
        return array_merge(self::collectionPaths(), self::detailPaths());
    }

    /**
     * What 398-rest-collection.yaml's `paths:` MUST equal (test-pinned, order-insensitive): every
     * collection noun under /api/v1, /api/v2, / and /admin — 12 × 4 = 48 keys.
     *
     * @return list<string>
     */
    public static function collectionPaths(): array
    {
        $paths = [];
        foreach (self::COLLECTION_NOUNS as $noun) {
            $paths[] = '/api/v1/' . $noun;
            $paths[] = '/api/v2/' . $noun;
            $paths[] = '/' . $noun;
            $paths[] = '/admin/' . $noun;
        }

        return $paths;
    }

    /**
     * What 399-rest-detail.yaml's `paths:` MUST equal (test-pinned): every detail noun under /api/v1.
     *
     * @return list<string>
     */
    public static function detailPaths(): array
    {
        $paths = [];
        foreach (self::DETAIL_NOUNS as $noun) {
            $paths[] = '/api/v1/' . $noun;
        }

        return $paths;
    }
}
