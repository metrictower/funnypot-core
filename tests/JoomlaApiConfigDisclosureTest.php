<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use Funnypot\Core\Template\DirectiveRenderer;
use PHPUnit\Framework\TestCase;

/**
 * FP-0452 — Joomla webservice config disclosure (CVE-2023-23752).
 *
 * The corpus already routes GET /api/index.php/v1/config/application (+ the /api/v1 alias) with a
 * single joomla bundle, but its bare serve synthesizes the body from the bundle words only
 * ('"links":' / '"attributes":') — it never carries user/password, so a credential-harvest scanner's
 * confirmation (body contains 'password' AND 'user' + a data[] element with attributes) fails. Route
 * 151 enriches those two keys, route_key-guarded, so the served body carries the leaked DB-credential
 * shape while preserving the original nuclei serve (the bundle words survive).
 *
 * The enrich fires only under a rich style (a MINIMAL deploy never runs route emulators), so the serve
 * assertions build the engine at REALISTIC/TAUNT against the committed production corpus.
 */
final class JoomlaApiConfigDisclosureTest extends TestCase
{
    private const KEY = 'GET /api/index.php/v1/config/application';

    private const PATH = '/api/index.php/v1/config/application';

    private const ALIAS = '/api/v1/config/application';

    private const ROUTES = __DIR__ . '/../resources/compiled/funnypot-routes.php';

    private const ID = 'route-joomla-api-config';

    private const SEEDS = ['0', '1', '7', '42', '777', '4242', '99999'];

    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    /** A respond-mode engine over the real compiled corpus, pinned to one seed and style. */
    private function engine(string $seed, string $style): Honeypot
    {
        return new Honeypot(new PhpArrayStore(self::index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style,
            'high',
            65536,
            0,
            0,
            false
        ));
    }

    /** The committed route body for $id — the exact template the route emulator renders. */
    private function routeBody(string $id): string
    {
        foreach ((array) (require self::ROUTES) as $rule) {
            if (is_array($rule) && ($rule['id'] ?? null) === $id) {
                return (string) ($rule['body'] ?? '');
            }
        }
        self::fail("route '{$id}' is not present in the compiled route artifact");
    }

    // --- the corpus bundle is intact (enrich forks no bundle) --------------------------------------

    public function test_key_still_served_and_single_bundle(): void
    {
        $routes = self::index()['routes'];
        foreach ([self::KEY, 'GET ' . self::ALIAS] as $key) {
            self::assertArrayHasKey($key, $routes, "{$key} must still be a compiled store key");
            $bundles = $routes[$key]['b'];
            self::assertCount(1, $bundles, "{$key} must stay a single-bundle key (enrich must not fork it)");
            self::assertSame('joomla', $bundles[0]['pid'], "{$key} pid");
            self::assertContains('CVE-2023-23752', $bundles[0]['t'], "{$key} must keep the CVE detection id");
        }
    }

    // --- the Tsunami confirmation predicate, served ------------------------------------------------

    public function test_tsunami_predicate(): void
    {
        foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
            foreach (self::SEEDS as $seed) {
                $r = $this->engine($seed, $style)->respond(new RequestContext('GET', self::PATH));
                $label = "seed {$seed} [{$style}]";

                self::assertNotNull($r, "{$label}: config path must serve");
                self::assertSame(200, $r->status, "{$label}: status");

                // Tsunami: body contains 'password' AND 'user'.
                self::assertStringContainsString('password', $r->body, "{$label}: body must contain 'password'");
                self::assertStringContainsString('user', $r->body, "{$label}: body must contain 'user'");

                // Tsunami: body parses as JSON, root data is an array, >=1 element has attributes.
                $json = json_decode($r->body, true);
                self::assertIsArray($json, "{$label}: body must be valid JSON");
                self::assertArrayHasKey('data', $json, "{$label}: root must carry data");
                self::assertIsArray($json['data'], "{$label}: data must be an array");
                $withAttrs = 0;
                $withCreds = 0;
                foreach ($json['data'] as $el) {
                    if (is_array($el) && isset($el['attributes']) && is_array($el['attributes'])) {
                        $withAttrs++;
                        if (isset($el['attributes']['user'], $el['attributes']['password'])) {
                            $withCreds++;
                        }
                    }
                }
                self::assertGreaterThanOrEqual(1, $withAttrs, "{$label}: >=1 data element with attributes");
                self::assertGreaterThanOrEqual(1, $withCreds, "{$label}: a data element carries user+password");
            }
        }
    }

    /**
     * Regression sentinel: the credential shape exists ONLY because of the enrich. The bare bundle
     * words the corpus ships ('"links":' / '"attributes":') never spell user/password, so a served
     * body that contains them proves the enrich fired, not an accident of the minimal synth.
     */
    public function test_no_op_would_fail_without_enrich(): void
    {
        $bundleWords = self::index()['routes'][self::KEY]['b'][0]['bw'];
        self::assertSame(['"links":', '"attributes":'], $bundleWords, 'corpus bundle words unchanged');
        self::assertStringNotContainsString('password', implode('', $bundleWords), 'bare bundle words carry no credential');
        self::assertStringNotContainsString('user', implode('', $bundleWords), 'bare bundle words carry no user');
    }

    // --- alias + query resolve to the same served witness -----------------------------------------

    public function test_alias_dressed_identically(): void
    {
        $inv = $this->engine('42', Style::REALISTIC);
        $main = $inv->respond(new RequestContext('GET', self::PATH));
        $alias = $inv->respond(new RequestContext('GET', self::ALIAS));
        self::assertNotNull($alias, 'alias must serve');
        self::assertSame(200, $alias->status, 'alias status');
        self::assertStringContainsString('password', $alias->body, 'alias body carries the witness');
        self::assertStringContainsString('"attributes":', $alias->body, 'alias keeps the bundle words');
        self::assertSame($main->body, $alias->body, 'alias serves the same body as the primary key');
    }

    public function test_query_variant_resolves(): void
    {
        $inv = $this->engine('42', Style::REALISTIC);
        $bare = $inv->respond(new RequestContext('GET', self::PATH));
        $withQuery = $inv->respond(new RequestContext('GET', self::PATH, 'public=true'));
        self::assertNotNull($withQuery, '?public=true must resolve (store key strips the query)');
        self::assertSame($bare->body, $withQuery->body, '?public=true serves the same body');
    }

    // --- media type is application/json (NOT vnd.api+json) -----------------------------------------

    /**
     * The bundle header witness is the substring 'application/json'. Serving
     * 'application/vnd.api+json' would fail bundle validation (it lacks that contiguous substring) and
     * silently drop the serve to the credential-less minimal body, so this pins the served media type.
     */
    public function test_media_type_is_application_json(): void
    {
        $r = $this->engine('7', Style::REALISTIC)->respond(new RequestContext('GET', self::PATH));
        $ct = $r->headers['Content-Type'] ?? '';
        self::assertIsString($ct);
        self::assertStringContainsString('application/json', $ct, 'served CT must contain application/json (bundle hw)');
        self::assertStringNotContainsString('vnd.api+json', $ct, 'served CT must not be application/vnd.api+json');
    }

    // --- the original CVE / nuclei serve is preserved ---------------------------------------------

    public function test_nuclei_serve_preserved(): void
    {
        $r = $this->engine('7', Style::REALISTIC)->respond(new RequestContext('GET', self::PATH));
        self::assertStringContainsString('"links":', $r->body, 'body must keep the bundle word "links":');
        self::assertStringContainsString('"attributes":', $r->body, 'body must keep the bundle word "attributes":');
    }

    // --- the route_key guard: the other joomla bundles are untouched -------------------------------

    /**
     * pid=joomla spans 17 bundles; the two-key route_key guard scopes the enrich to exactly the config
     * path + alias. Every other joomla key must serve its own body, never the credential shape.
     */
    public function test_other_joomla_bundles_untouched(): void
    {
        $inv = $this->engine('42', Style::REALISTIC);
        $others = ['/README.txt', '/administrator/manifests/files/joomla.xml', '/language/en-GB/en-GB.xml'];
        foreach ($others as $path) {
            $r = $inv->respond(new RequestContext('GET', $path));
            if ($r === null) {
                continue; // a corpus key that resolves to nothing is trivially untouched
            }
            self::assertStringNotContainsString('dbtype', $r->body, "{$path} must not serve the credential body");
            self::assertStringNotContainsString('dbprefix', $r->body, "{$path} must not serve the DB shape");
        }
    }

    // --- persona coherence: db creds match every other leaked-config surface -----------------------

    public function test_persona_coherence(): void
    {
        $renderSeed = crc32('a.example|s');
        $seedA = PersonaIdentity::seedFromMaterial('fp-0452-a');
        $seedB = PersonaIdentity::seedFromMaterial('fp-0452-b');

        $bodyA = (new DirectiveRenderer($seedA))->render($this->routeBody(self::ID), [], $renderSeed);
        $bodyB = (new DirectiveRenderer($seedB))->render($this->routeBody(self::ID), [], $renderSeed);

        self::assertSame(1, preg_match('/"password":"([^"]+)"/', $bodyA, $mA), 'A: db password renders');
        self::assertSame(1, preg_match('/"password":"([^"]+)"/', $bodyB, $mB), 'B: db password renders');
        self::assertNotSame($mA[1], $mB[1], 'two deploys must render different db passwords');

        // Same deploy → the password here equals the one on the other leaked-config surfaces.
        $secrets = (new DirectiveRenderer($seedA))->render($this->routeBody('route-secrets-json'), [], $renderSeed);
        self::assertSame(1, preg_match('/"password": "([^"]+)"/', $secrets, $mS), 'secrets.json db password renders');
        self::assertSame($mA[1], $mS[1], 'same deploy → same DB password across leaked-config surfaces');
    }

    // --- rendered bytes are fingerprint-clean -----------------------------------------------------

    public function test_fingerprint_safe(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $renderSeed = crc32('a.example|s');
        foreach (['', 'fp-0452-1', 'fp-0452-2', 'fp-0452-3'] as $mat) {
            $seed = PersonaIdentity::seedFromMaterial($mat);
            $body = (new DirectiveRenderer($seed))->render($this->routeBody(self::ID), [], $renderSeed);
            self::assertSame([], $guard->scan($body), "m=[{$mat}] rendered body must be fingerprint-clean");
        }
    }
}
