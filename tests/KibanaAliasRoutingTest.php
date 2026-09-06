<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteBundleSynth;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\RouteTemplateSet;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * The bare Kibana mounts (`GET /kibana`, `GET /kibana/`) are new-page aliases owned by route 372
 * (route-kibana), the same rule that enriches the corpus `/app/kibana(/)` bundles. A request to a
 * path with no compiled key falls out of core entirely (respond() returns null and the app serves
 * its own fallback), so the load-bearing claim here is that BOTH aliases are compiled keys whose one
 * bundle selects the authored shell — not a minimal synth of the bare body words, and never nothing.
 *
 * Pins the fold shape (exactly two exact GET keys, one bundle each), the served bytes per seed and
 * style, core's standard method/case/slash fallback around them, the negative controls that must
 * stay outside the alias, and the unchanged identity of the corpus `/app/kibana` routes.
 */
final class KibanaAliasRoutingTest extends TestCase
{
    private const ID = 'route-kibana';
    private const KEYS = ['GET /kibana', 'GET /kibana/'];
    private const CONTENT_TYPE = 'text/html; charset=utf-8';
    private const MARKERS = ['kibanaWelcomeView', '<title>Kibana</title>', 'kbn-injected-metadata', '"version":"7.17.18"'];
    private const SEEDS = ['0', '1', '2', '7', '42', '777', '4242', '99999'];

    /**
     * The corpus bundles route 372 has always enriched, byte-for-byte as compiled. The alias fold
     * must never rewrite these (a new bundle appended, a pid rewritten, a t-id dropped).
     */
    private const APP_KIBANA_BUNDLES = [
        'GET /app/kibana' => [[
            's' => 200,
            'bw' => ['kibanaWelcomeView', '<title>Kibana</title>'],
            'hw' => [],
            'nf' => [],
            'sz' => null,
            'rx' => [],
            'h' => [],
            'pid' => 'kibana',
            'sev' => 'medium',
            'sig' => 0,
            't' => ['exposed-kibana', 'kibana-panel'],
        ]],
        'GET /app/kibana/' => [[
            's' => 200,
            'bw' => ['kibanaWelcomeView'],
            'hw' => [],
            'nf' => [],
            'sz' => null,
            'rx' => [],
            'h' => [],
            'pid' => 'kibana',
            'sev' => 'medium',
            'sig' => 0,
            't' => ['exposed-kibana'],
        ]],
    ];

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
    private function engine(string $seed, string $style, bool $attackEmulation = false): Honeypot
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
            $attackEmulation
        ));
    }

    // --- fold shape --------------------------------------------------------------------------------

    /**
     * The synth is directory-scoped, so filter its fragment down to this rule's pid: exactly the two
     * bare GET keys, one bundle each, and nothing else — no prefix, encoded, nested, or non-GET key.
     */
    public function test_synth_fragment_emits_exactly_the_two_bare_get_aliases(): void
    {
        $dirs = [__DIR__ . '/../templates/route', __DIR__ . '/../templates/generated'];
        $fragment = (new RouteBundleSynth())->fragmentDirs($dirs);

        $mine = [];
        foreach ($fragment['routes'] as $key => $bundles) {
            foreach ($bundles as $b) {
                if (($b['pid'] ?? '') === self::ID) {
                    $mine[$key][] = $b;
                }
            }
        }
        ksort($mine);
        self::assertSame(self::KEYS, array_keys($mine), 'the Kibana rule must fold exactly the two bare GET aliases');
        foreach ($mine as $key => $bundles) {
            self::assertCount(1, $bundles, "{$key} must carry one alias bundle");
            self::assertSame(200, $bundles[0]['s'], "{$key} status");
            self::assertSame('medium', $bundles[0]['sev'], "{$key} severity");
            self::assertSame(0, $bundles[0]['sig'], "{$key} must be a probe (sig 0), never signature-gated");
            self::assertSame([self::ID], $bundles[0]['t'], "{$key} must carry the rule id as its sole template id");
            self::assertSame(['kibanaWelcomeView', '<title>Kibana</title>'], $bundles[0]['bw'], "{$key} body words");
        }
        self::assertArrayHasKey(self::ID, $fragment['templates'], 'the fold must register the alias template');

        // Two independent runs of the synth agree byte-for-byte (the artifact law depends on it).
        self::assertSame(serialize($fragment), serialize((new RouteBundleSynth())->fragmentDirs($dirs)), 'the fragment must be deterministic');
    }

    /**
     * The committed full index carries the fold: both keys present with one route-kibana bundle each,
     * the template registered, and NO other key anywhere in the corpus carrying this pid (a stray fold
     * would give the alias body to an unrelated path).
     */
    public function test_compiled_index_keys_exactly_the_two_aliases(): void
    {
        $index = self::index();
        self::assertArrayHasKey(self::ID, $index['templates'] ?? [], 'templates table must carry route-kibana');

        $keyed = [];
        foreach ($index['routes'] as $key => $entry) {
            foreach ((array) ($entry['b'] ?? []) as $b) {
                if (($b['pid'] ?? '') === self::ID) {
                    $keyed[$key][] = $b;
                }
            }
        }
        ksort($keyed);
        self::assertSame(self::KEYS, array_keys($keyed), 'route-kibana bundles must sit at exactly the two bare aliases');
        foreach (self::KEYS as $key) {
            self::assertCount(1, $index['routes'][$key]['b'], "{$key} must be a single-bundle key");
            self::assertSame([self::ID], $index['routes'][$key]['b'][0]['t'], "{$key} sole template id");
        }
    }

    // --- served bytes ------------------------------------------------------------------------------

    /**
     * Across seeds × styles, with and without a query, both aliases detect, serve 200 text/html, carry
     * every authored `expect` marker, and satisfy the alias bundle — the same shell the corpus
     * `/app/kibana` route serves for that seed/style, byte for byte.
     */
    public function test_aliases_detect_and_serve_the_authored_shell_across_seeds(): void
    {
        foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
            foreach (self::SEEDS as $seed) {
                $inv = $this->engine($seed, $style);
                $corpus = $inv->respond(new RequestContext('GET', '/app/kibana'));
                self::assertNotNull($corpus, "seed {$seed} [{$style}]: /app/kibana must serve");

                foreach (['/kibana', '/kibana/'] as $path) {
                    foreach (['', 'a=b'] as $query) {
                        $label = "seed {$seed} [{$style}]: GET {$path}" . ($query === '' ? '' : "?{$query}");

                        self::assertTrue($inv->detect(new RequestContext('GET', $path, $query))->matched, "{$label} must be detected");

                        $r = $inv->respond(new RequestContext('GET', $path, $query));
                        self::assertNotNull($r, "{$label} must serve a fake, never fall out of core");
                        self::assertSame(200, $r->status, "{$label} status");
                        self::assertSame(self::CONTENT_TYPE, $r->headers['Content-Type'] ?? null, "{$label} Content-Type");
                        self::assertSame([self::ID], $r->satisfies->templateIds(), "{$label} must satisfy the alias bundle");
                        foreach (self::MARKERS as $marker) {
                            self::assertStringContainsString($marker, $r->body, "{$label} must carry {$marker}");
                        }
                        self::assertSame($corpus->body, $r->body, "{$label} must serve the same shell as /app/kibana");
                    }
                }
            }
        }
    }

    // --- method / path fallback around the exact keys ------------------------------------------------

    /**
     * Only GET keys are folded; these resolve through resolveEntry()'s standard fallback (POST/HEAD to
     * GET, one slash flip, lower-casing the untrimmed path). Each variant is checked on its own — the
     * fallback composes one step at a time, so a case change AND a doubled slash together is a miss
     * by design and is deliberately not pinned either way. Core does not blank a HEAD body, so HEAD
     * carries the markers too.
     */
    public function test_standard_method_and_path_fallback_reaches_the_alias(): void
    {
        $inv = $this->engine('7', Style::REALISTIC);
        $variants = [
            ['HEAD', '/kibana'],
            ['HEAD', '/kibana/'],
            ['POST', '/kibana'],
            ['POST', '/kibana/'],
            ['GET', '/Kibana'],
            ['GET', '/Kibana/'],
            ['GET', '/kibana//'],
        ];
        foreach ($variants as [$method, $path]) {
            $r = $inv->respond(new RequestContext($method, $path));
            self::assertNotNull($r, "{$method} {$path} must reach the alias through the standard fallback");
            self::assertSame(200, $r->status, "{$method} {$path} status");
            self::assertSame(self::CONTENT_TYPE, $r->headers['Content-Type'] ?? null, "{$method} {$path} Content-Type");
            self::assertSame([self::ID], $r->satisfies->templateIds(), "{$method} {$path} must satisfy the alias bundle");
            self::assertStringContainsString('kbn-injected-metadata', $r->body, "{$method} {$path} must serve the authored shell");
        }
    }

    /**
     * Verbs a real server answers differently, encoded and nested spellings, and the login endpoint
     * gain no alias ownership: they never serve the authored Kibana shell. Unmatched verbs and the
     * variant spellings resolve to nothing; OPTIONS/TRACE on the bare mount get FP-0011's bounded
     * generic method coverage (a closed 204/405), which is not the alias — it serves no body and
     * never satisfies route-kibana.
     */
    public function test_negative_controls_gain_no_alias_ownership(): void
    {
        $inv = $this->engine('7', Style::REALISTIC);
        $nullControls = [
            ['PUT', '/kibana'],
            ['DELETE', '/kibana'],
            ['GET', '/%6bibana'],
            ['GET', '/kibana%2f'],
            ['GET', '/foo/kibana'],
            ['GET', '/kibana/app'],
            ['GET', '/internal/security/login'],
        ];
        foreach ($nullControls as [$method, $path]) {
            self::assertNull($inv->respond(new RequestContext($method, $path)), "{$method} {$path} must not resolve to the alias");
        }

        // OPTIONS/TRACE get generic method coverage, never the alias shell.
        foreach ([['OPTIONS', 204], ['TRACE', 405]] as [$method, $status]) {
            $r = $inv->respond(new RequestContext($method, '/kibana'));
            self::assertNotNull($r, "{$method} /kibana is method-covered");
            self::assertSame($status, $r->status, "{$method} /kibana");
            self::assertSame('', $r->body, "{$method} /kibana must serve no body");
            self::assertNotContains(self::ID, $r->satisfies->templateIds(), "{$method} /kibana must not satisfy the alias");
        }
    }

    /**
     * The pid selector shares the rule with the enrich needle; neither may reach the attack tier.
     * `POST /internal/security/login` stays with the request-aware login oracle — the served bytes
     * are its 401, satisfying the attack rule id and never route-kibana.
     */
    public function test_login_oracle_is_untouched_by_the_alias_selector(): void
    {
        $inv = $this->engine('7', Style::REALISTIC, true);
        $r = $inv->respond(new RequestContext('POST', '/internal/security/login', '', ['kbn-xsrf' => 'true'], '{}'));
        self::assertNotNull($r, 'the login oracle must still answer');
        self::assertSame(401, $r->status);
        self::assertSame(['attack-kibana-login'], $r->satisfies->templateIds(), 'the oracle owns its path; the alias pid must not');
        self::assertStringNotContainsString('kibanaWelcomeView', $r->body, 'the alias shell must never serve on the login endpoint');
    }

    // --- the corpus routes this rule has always enriched -------------------------------------------

    /**
     * The fold appends keys; it must not touch the corpus `/app/kibana(/)` entries. Their bundle arrays
     * stay byte-identical to the pre-fold compile, they still select route 372 through the needle,
     * and they render the same status / content type / markers as the aliases.
     */
    public function test_corpus_app_kibana_routes_keep_their_identity_and_rendering(): void
    {
        $routes = self::index()['routes'];
        $set = RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');

        foreach (self::APP_KIBANA_BUNDLES as $key => $expected) {
            self::assertSame($expected, $routes[$key]['b'] ?? null, "{$key} bundle array must be unchanged by the alias fold");

            $rule = $set->findRule($routes[$key]['b'][0]);
            self::assertNotNull($rule, "{$key} must still select a route rule");
            self::assertSame(self::ID, $rule['id'], "{$key} must still select route-kibana through the needle");
        }

        foreach ([Style::REALISTIC, Style::TAUNT] as $style) {
            $inv = $this->engine('42', $style);
            foreach (['/app/kibana' => ['exposed-kibana', 'kibana-panel'], '/app/kibana/' => ['exposed-kibana']] as $path => $ids) {
                $r = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($r, "[{$style}] {$path} must serve");
                self::assertSame(200, $r->status, "[{$style}] {$path} status");
                self::assertSame(self::CONTENT_TYPE, $r->headers['Content-Type'] ?? null, "[{$style}] {$path} Content-Type");
                self::assertSame($ids, $r->satisfies->templateIds(), "[{$style}] {$path} must keep its corpus detection ids");
                foreach (self::MARKERS as $marker) {
                    self::assertStringContainsString($marker, $r->body, "[{$style}] {$path} must carry {$marker}");
                }
            }
        }
    }
}
