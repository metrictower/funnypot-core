<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * FP-0316 — route-context (route_key) semantics.
 *
 * A route template may declare `match.route_key`: a conjunctive GUARD, never a fourth OR axis. The
 * compiler validates its shape and rejects a route-key-only rule; RouteTemplateSet::selects() applies
 * it as an exact-key precondition. A null key (a direct call / embedded host) can never satisfy a
 * guarded rule, so unguarded legacy rules keep first-match-wins and the path-aware listings decline
 * cleanly rather than falling back to a wrong /backup page.
 */
final class RouteTemplateContextTest extends TestCase
{
    /** @param array<string,mixed> $doc @return array<string,mixed> */
    private function normalizeRoute(array $doc): array
    {
        $compiler = new RouteEmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'route-ctx-test.yaml');
    }

    /** A minimal well-formed enrich doc with the given match block. @param array<string,mixed> $match */
    private function docWithMatch(array $match): array
    {
        return [
            'id' => 'route-ctx-test',
            'priority' => 180,
            'match' => $match,
            'response' => [
                'headers' => ['Content-Type' => 'text/html; charset=utf-8'],
                'body' => "<html><head><title>Index of /backup</title></head><body>x</body></html>\n",
            ],
        ];
    }

    // --- compiler validation ---------------------------------------------------------------------

    public function test_route_key_guard_compiles_and_is_preserved(): void
    {
        $rule = $this->normalizeRoute($this->docWithMatch([
            'template_needle' => ['directory-listing'],
            'route_key' => ['GET /backup/'],
        ]));

        self::assertSame(['directory-listing'], $rule['match']['template_needle']);
        self::assertSame(['GET /backup/'], $rule['match']['route_key'], 'the exact route key must survive compilation');
    }

    public function test_route_key_only_rule_is_rejected(): void
    {
        // route_key is a guard, not a selector — a rule with no template_needle/pid/body_word_contains
        // would dress every bundle that ever resolves at that key.
        $this->expectException(RuntimeException::class);
        $this->normalizeRoute($this->docWithMatch(['route_key' => ['GET /backup/']]));
    }

    public function test_unknown_match_key_is_rejected(): void
    {
        // The match vocabulary is closed; a typo would silently widen/narrow selection.
        $this->expectException(RuntimeException::class);
        $this->normalizeRoute($this->docWithMatch([
            'template_needle' => ['directory-listing'],
            'route_keys' => ['GET /backup/'], // typo: plural
        ]));
    }

    /** @return array<string,array{0:string}> */
    public static function malformedKeys(): array
    {
        return [
            'lowercase method'  => ['get /backup/'],
            'unknown method'    => ['FETCH /backup/'],
            'no space'          => ['GET/backup/'],
            'relative path'     => ['GET backup/'],
            'carries a query'   => ['GET /backup/?x=1'],
            'carries a fragment' => ['GET /backup/#frag'],
            'embedded space'    => ['GET /back up/'],
            'control byte'      => ["GET /backup/\t"],
        ];
    }

    /** @dataProvider malformedKeys */
    public function test_malformed_route_key_is_rejected(string $key): void
    {
        $this->expectException(RuntimeException::class);
        $this->normalizeRoute($this->docWithMatch([
            'template_needle' => ['directory-listing'],
            'route_key' => [$key],
        ]));
    }

    public function test_duplicate_route_key_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->normalizeRoute($this->docWithMatch([
            'template_needle' => ['directory-listing'],
            'route_key' => ['GET /backup/', 'GET /backup/'],
        ]));
    }

    public function test_empty_route_key_entry_is_rejected(): void
    {
        $this->expectException(RuntimeException::class);
        $this->normalizeRoute($this->docWithMatch([
            'template_needle' => ['directory-listing'],
            'route_key' => [''],
        ]));
    }

    // --- selects() semantics ---------------------------------------------------------------------

    private function guardedSet(): RouteTemplateSet
    {
        return new RouteTemplateSet([
            ['id' => 'guarded', 'match' => ['template_needle' => ['directory-listing'], 'route_key' => ['GET /backup/']], 'body' => 'x', 'headers' => []],
            ['id' => 'unguarded', 'match' => ['template_needle' => ['other-needle']], 'body' => 'y', 'headers' => []],
        ]);
    }

    public function test_guard_needs_exact_key_and_a_matching_axis(): void
    {
        $set = $this->guardedSet();
        $bundle = ['pid' => 'x', 't' => ['directory-listing'], 'bw' => []];

        // key + axis both match → selected
        $rule = $set->findRule($bundle, 'GET /backup/');
        self::assertNotNull($rule);
        self::assertSame('guarded', $rule['id']);
    }

    public function test_guard_declines_on_a_wrong_key(): void
    {
        $set = $this->guardedSet();
        $bundle = ['pid' => 'x', 't' => ['directory-listing'], 'bw' => []];
        self::assertNull($set->findRule($bundle, 'GET /other/'), 'a wrong key must decline the guarded rule');
    }

    public function test_guard_declines_on_a_null_key(): void
    {
        $set = $this->guardedSet();
        $bundle = ['pid' => 'x', 't' => ['directory-listing'], 'bw' => []];
        self::assertNull($set->findRule($bundle), 'a null key can never satisfy a guarded rule');
    }

    public function test_guard_declines_on_a_wrong_bundle_even_with_the_right_key(): void
    {
        $set = $this->guardedSet();
        $bundle = ['pid' => '', 't' => ['unrelated'], 'bw' => []]; // needle does not match
        self::assertNull($set->findRule($bundle, 'GET /backup/'), 'the axis must still match — the key alone is not a selector');
    }

    public function test_unguarded_rule_is_route_key_blind(): void
    {
        $set = $this->guardedSet();
        $bundle = ['pid' => '', 't' => ['other-needle'], 'bw' => []];
        // An unguarded rule keeps its first-match OR behaviour for any key, including null.
        self::assertSame('unguarded', $set->findRule($bundle)['id']);
        self::assertSame('unguarded', $set->findRule($bundle, 'GET /anything/')['id']);
    }

    // --- shipped corpus: null-context fallback ---------------------------------------------------

    private function shippedSet(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    /** @return array<string,mixed> the directory-listing bundle compiled at a route key */
    private function dirListingBundle(string $routeKey, int $i): array
    {
        $idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';

        return $idx['routes'][$routeKey]['b'][$i];
    }

    public function test_shipped_listing_bundle_declines_without_its_route_key(): void
    {
        // The whole defect FP-0316 fixes: a directory-listing bundle must NOT fall back to some other
        // listing's body. With the generic enrich retired, a null key selects nothing.
        $bundle = $this->dirListingBundle('GET /backup/', 0);
        self::assertNull($this->shippedSet()->findRule($bundle), 'a shipped listing bundle must not select any rule without its key');
    }

    public function test_shipped_listing_bundle_selects_its_own_path_aware_rule(): void
    {
        $set = $this->shippedSet();
        $cases = [
            'GET /backup/' => 'route-dirlist-backup',
            'GET /wp-includes/' => 'route-dirlist-wp-includes',
            'GET /glpi/' => 'route-dirlist-glpi',
        ];
        foreach ($cases as $key => $id) {
            $rule = $set->findRule($this->dirListingBundle($key, 0), $key);
            self::assertNotNull($rule, "{$key} must select a rule with its key");
            self::assertSame($id, $rule['id'], "{$key} must select its own path-aware rule");
        }
    }

    // --- facade / position-blind equality --------------------------------------------------------

    /** @param array<string,string> $headers @return array<string,string> */
    private function headersExceptRequestId(array $headers): array
    {
        unset($headers['X-Request-Id']);

        return $headers;
    }

    public function test_facade_and_port_render_a_path_aware_listing_identically(): void
    {
        // The route key is threaded from the resolved handle (never request bytes), so respond()
        // (facade) and synthesizeFromHandle() (position-blind port) must produce identical bytes.
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $engine = new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'listing-seed'; },
            'coherent',
            'realistic'
        ));
        $profile = SiteProfile::empty();

        $verdict = $engine->classify(new RequestContext('GET', '/backup/', '', [], null, 'example.com'), $profile);
        self::assertNotNull($verdict->fakeHandle, '/backup/ must produce a route handle');

        $viaVerdict = $engine->synthesize($verdict, $profile, 'listing-seed');
        $viaHandle = $engine->synthesizeFromHandle($verdict->fakeHandle, $profile, 'listing-seed');

        self::assertNotNull($viaVerdict);
        self::assertNotNull($viaHandle);
        self::assertStringContainsString('Index of /backup', $viaVerdict->body, 'the path-aware body must serve, not a generic one');
        self::assertSame($viaVerdict->status, $viaHandle->status);
        self::assertSame($viaVerdict->body, $viaHandle->body, 'facade and port must render one handle to identical bytes');
        self::assertSame(
            $this->headersExceptRequestId($viaVerdict->headers),
            $this->headersExceptRequestId($viaHandle->headers)
        );
    }
}
