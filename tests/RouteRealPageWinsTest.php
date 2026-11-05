<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Compiler\RichBundleStamp;
use Funnypot\Core\Config;
use Funnypot\Core\Detection;
use Funnypot\Core\FakeHandle;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaSelector;
use Funnypot\Core\Synthesis\ResponseSynthesizer;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use ReflectionProperty;

/**
 * A real decoy page wins over bare matcher words on a mixed route key: when the persona pick lands on a
 * bundle that renders minimal, the engine serves one of the build-stamped bundles that renders rich.
 * Runs on the full compiled corpus.
 */
final class RouteRealPageWinsTest extends TestCase
{
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

    private static function config(
        string $style = Style::REALISTIC,
        int $maxBody = 65536,
        bool $attack = false,
        string $salt = '',
        ?string $deploySeed = 'route-real-page-wins'
    ): Config {
        return new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            $style,
            'critical',
            $maxBody,
            0,
            0,
            $attack,
            null,
            null,
            static function (RequestContext $r): bool {
                return true;
            },
            $salt,
            [],
            true,
            null,
            null,
            null,
            $deploySeed
        );
    }

    private static function engine(Config $config): Honeypot
    {
        return new Honeypot(new PhpArrayStore(self::index()), $config);
    }

    private static function request(string $path, string $host, string $method = 'GET'): RequestContext
    {
        return new RequestContext($method, $path, '', ['user-agent' => 'Mozilla/5.0', 'host' => $host], null, $host, 'http');
    }

    /** @return array<int,string> */
    private static function hosts(int $n): array
    {
        $hosts = [];
        for ($i = 0; $i < $n; $i++) {
            $hosts[] = 'h' . $i . '.example';
        }

        return $hosts;
    }

    private static function synth(Honeypot $engine): ResponseSynthesizer
    {
        $p = new ReflectionProperty(Honeypot::class, 'synthesizer');
        $p->setAccessible(true);

        return $p->getValue($engine);
    }

    /** A minimal-only synthesizer sharing the engine's deploy identity. */
    private static function minimalSynth(Honeypot $engine): ResponseSynthesizer
    {
        $p = new ReflectionProperty(ResponseSynthesizer::class, 'deploySeed');
        $p->setAccessible(true);

        return new ResponseSynthesizer(null, Style::MINIMAL, null, null, $p->getValue(self::synth($engine)));
    }

    /**
     * @param array<int,array<string,mixed>> $bundles
     * @return array<int,array<string,mixed>>
     */
    private static function candidates(Honeypot $engine, array $bundles): array
    {
        $m = new ReflectionMethod(Honeypot::class, 'candidates');
        $m->setAccessible(true);

        return $m->invoke($engine, $bundles);
    }

    /** @param array<int,string> $ids */
    private static function detection(Honeypot $engine, string $key, array $ids): Detection
    {
        $m = new ReflectionMethod(Honeypot::class, 'detectionFor');
        $m->setAccessible(true);

        return $m->invoke($engine, $key, $ids);
    }

    /** @return array<string,array<string,mixed>> stamped GET entries */
    private static function stampedEntries(): array
    {
        $out = [];
        foreach (self::index()['routes'] as $key => $entry) {
            if (isset($entry[RichBundleStamp::KEY])) {
                $out[(string) $key] = $entry;
            }
        }

        return $out;
    }

    /** Today's pick (persona pick over all servable bundles) and its render. */
    private static function todaysRender(Honeypot $engine, Config $config, string $key, array $entry, string $host): ?array
    {
        $candidates = self::candidates($engine, array_values($entry['b']));
        if ($candidates === []) {
            return null;
        }
        $seed = $config->seedFor(self::request(substr($key, 4), $host));
        $picked = PersonaSelector::pick($candidates, $seed);
        $synth = self::synth($engine);
        $resp = $synth->synthesize($picked, self::detection($engine, $key, $picked['t'] ?? []), $seed, $key);

        return ['bundle' => $picked, 'response' => $resp, 'rich' => $synth->lastRenderedRich(), 'seed' => $seed];
    }

    private static function bodyAndType(?SynthesizedResponse $r): ?array
    {
        return $r === null ? null : [$r->body, $r->headers['Content-Type'] ?? null];
    }

    public function test_stamp_is_present_and_non_vacuous(): void
    {
        $stamped = self::stampedEntries();
        self::assertGreaterThanOrEqual(50, count($stamped), 'the build must stamp the mixed GET keys');
        foreach (['GET /wp-login.php', 'GET /login', 'GET /favicon.ico'] as $key) {
            self::assertArrayHasKey($key, $stamped, $key);
        }
        self::assertArrayNotHasKey('GET /', $stamped, 'the persona root is never stamped');
    }

    public function test_stamped_keys_serve_a_rich_render_in_realistic_style(): void
    {
        $config = self::config();
        $engine = self::engine($config);
        $synth = self::synth($engine);
        $minimal = self::minimalSynth($engine);
        $checked = 0;

        foreach (self::stampedEntries() as $key => $entry) {
            $path = substr($key, 4);
            $bundles = array_values($entry['b']);
            foreach (self::hosts(25) as $host) {
                $seed = $config->seedFor(self::request($path, $host));

                // Precondition: some stamped, servable bundle renders rich for this seed.
                $canRich = false;
                foreach ((array) $entry[RichBundleStamp::KEY] as $i) {
                    if (self::candidates($engine, [$bundles[$i]]) === []) {
                        continue;
                    }
                    $synth->synthesize($bundles[$i], self::detection($engine, $key, $bundles[$i]['t'] ?? []), $seed, $key);
                    if ($synth->lastRenderedRich()) {
                        $canRich = true;
                        break;
                    }
                }
                if (!$canRich) {
                    continue;
                }

                $served = $engine->respond(self::request($path, $host));
                self::assertNotNull($served, "{$key} @ {$host}");
                self::assertSame(FakeHandle::KIND_ROUTE, $served->servedBy->kind, "{$key} @ {$host}");
                foreach ($bundles as $b) {
                    $bare = $minimal->synthesize($b, self::detection($engine, $key, $b['t'] ?? []), $seed, $key);
                    if ($bare !== null) {
                        self::assertNotSame($bare->body, $served->body, "{$key} @ {$host} served bare matcher words");
                    }
                }
                $checked++;
            }
        }

        self::assertGreaterThan(500, $checked, 'the sweep must exercise the stamped keys');
    }

    public function test_lab_repro_host_gets_the_login_page(): void
    {
        $engine = self::engine(self::config(Style::REALISTIC, 65536, true, 'fp0769-lab', 'fp0769-lab-deploy-seed'));
        $r = $engine->respond(self::request('/wp-login.php', '127.0.0.1:18171'));

        self::assertNotNull($r);
        self::assertStringContainsString('text/html', (string) ($r->headers['Content-Type'] ?? ''));
        self::assertStringContainsString('<form', $r->body);
        self::assertNotSame("#039;\"=\nwpml_lang", $r->body);
    }

    public function test_hosts_already_served_a_real_page_are_unchanged(): void
    {
        $config = self::config();
        $engine = self::engine($config);
        $kept = 0;

        foreach (self::stampedEntries() as $key => $entry) {
            foreach (self::hosts(15) as $host) {
                $today = self::todaysRender($engine, $config, $key, $entry, $host);
                if ($today === null || !$today['rich'] || $today['response'] === null) {
                    continue;
                }
                $served = $engine->respond(self::request(substr($key, 4), $host));
                self::assertSame(self::bodyAndType($today['response']), self::bodyAndType($served), "{$key} @ {$host}");
                $kept++;
            }
        }

        self::assertGreaterThan(100, $kept);
    }

    public function test_failed_rich_render_keeps_todays_pick(): void
    {
        $config = self::config();
        $engine = self::engine($config);
        $entry = self::index()['routes']['GET /admin/index.php'];
        self::assertArrayHasKey(RichBundleStamp::KEY, $entry, 'the key must stay stamped for this test to mean anything');

        foreach (self::hosts(25) as $host) {
            $today = self::todaysRender($engine, $config, 'GET /admin/index.php', $entry, $host);
            $served = $engine->respond(self::request('/admin/index.php', $host));
            self::assertSame(self::bodyAndType($today['response']), self::bodyAndType($served), $host);
        }
    }

    public function test_lowered_body_cap_never_adds_a_null(): void
    {
        $config = self::config(Style::REALISTIC, 1024);
        $engine = self::engine($config);
        $index = self::index();

        foreach (['GET /login', 'GET /admin.php', 'GET /console', 'GET /wp-login.php'] as $key) {
            foreach (self::hosts(30) as $host) {
                $today = self::todaysRender($engine, $config, $key, $index['routes'][$key], $host);
                if ($today === null || $today['response'] === null || strlen($today['response']->body) > 1024) {
                    continue;
                }
                self::assertNotNull($engine->respond(self::request(substr($key, 4), $host)), "{$key} @ {$host}");
            }
        }
    }

    public function test_minimal_style_is_unchanged(): void
    {
        $engine = self::engine(self::config(Style::MINIMAL));

        $favicons = [];
        $stubOnLogin = false;
        foreach (self::hosts(40) as $host) {
            $f = $engine->respond(self::request('/favicon.ico', $host));
            if ($f !== null) {
                $favicons[md5($f->body)] = true;
            }
            $w = $engine->respond(self::request('/wp-login.php', $host));
            if ($w !== null && array_intersect(['wpml-xss', 'CVE-2022-4301'], $w->satisfies->templateIds()) !== []) {
                $stubOnLogin = true;
            }
        }

        self::assertGreaterThan(1, count($favicons), 'minimal keeps the favicon bait variety');
        self::assertTrue($stubOnLogin, 'minimal still serves the stub bundles on /wp-login.php');
    }

    public function test_root_pick_matches_the_persona_gate(): void
    {
        $config = self::config();
        $engine = self::engine($config);
        $entry = self::index()['routes']['GET /'];
        $synth = self::synth($engine);

        foreach (self::hosts(25) as $host) {
            $seed = $config->seedFor(self::request('/', $host));
            $picked = PersonaSelector::pick(self::candidates($engine, array_values($entry['b'])), $seed);
            $expected = $synth->synthesize($picked, self::detection($engine, 'GET /', $picked['t'] ?? []), $seed, 'GET /');
            $served = $engine->synthesizeFromHandle(FakeHandle::route('GET /'), SiteProfile::empty(), $seed);
            self::assertSame(self::bodyAndType($expected), self::bodyAndType($served), $host);
        }
    }

    public function test_selection_is_deterministic(): void
    {
        $engine = self::engine(self::config());

        foreach (array_keys(self::stampedEntries()) as $key) {
            foreach (self::hosts(5) as $host) {
                $a = $engine->respond(self::request(substr($key, 4), $host));
                $b = $engine->respond(self::request(substr($key, 4), $host));
                self::assertSame(self::bodyAndType($a), self::bodyAndType($b), "{$key} @ {$host}");
            }
        }
    }

    /** @return array<string,array<string,mixed>> */
    private static function fixtureBundles(): array
    {
        $login = ['pid' => 'wordpress', 'sev' => 'info', 'sig' => 0, 'amb' => 0, 't' => ['wordpress-login'], 's' => 200,
            'bw' => [], 'hw' => [], 'nf' => [], 'sz' => null, 'rx' => [], 'h' => []];
        // Matches the same rich rule but demands a typed JSON Content-Type the login page never carries.
        $bad = $login;
        $bad['th'] = ['Content-Type' => ['application/json']];
        $stub = ['pid' => 'fixture', 'sev' => 'info', 'sig' => 0, 'amb' => 0, 't' => ['fixture-stub'], 's' => 200,
            'bw' => ['zz-fixture-stub-zz'], 'hw' => [], 'nf' => [], 'sz' => null, 'rx' => [], 'h' => []];

        return ['login' => $login, 'bad' => $bad, 'stub' => $stub];
    }

    /** @param array<string,array<string,mixed>> $routes */
    private static function fixtureEngine(array $routes): Honeypot
    {
        $index = ['schema' => 1, 'manifest' => [], 'routes' => $routes, 'templates' => [
            'wordpress-login' => ['sev' => 'info', 'tags' => ['panel', 'wordpress'], 'name' => 'login'],
            'fixture-stub' => ['sev' => 'info', 'tags' => ['fixture'], 'name' => 'stub'],
        ]];

        return new Honeypot(new PhpArrayStore($index), self::config());
    }

    /**
     * A host whose pick over $first lands on $want, and (when given) whose pick over $second lands on
     * $want2, so the path under test is really exercised.
     */
    private static function hostPicking(array $first, array $want, array $second = [], array $want2 = []): string
    {
        $config = self::config();
        foreach (self::hosts(500) as $host) {
            $seed = $config->seedFor(self::request('/wp-login.php', $host));
            if (PersonaSelector::pick($first, $seed) !== $want) {
                continue;
            }
            if ($second !== [] && PersonaSelector::pick($second, $seed) !== $want2) {
                continue;
            }

            return $host;
        }
        self::fail('no host in the grid picks the wanted bundles');
    }

    public function test_drop_and_repick_with_a_fixture_store(): void
    {
        $f = self::fixtureBundles();
        $routes = ['GET /wp-login.php' => ['b' => [$f['bad'], $f['login'], $f['stub']], RichBundleStamp::KEY => [0, 1]]];
        // Today's pick is the stub and the first stamped try is the failing bundle.
        $host = self::hostPicking([$f['bad'], $f['login'], $f['stub']], $f['stub'], [$f['bad'], $f['login']], $f['bad']);
        $engine = self::fixtureEngine($routes);

        $served = $engine->respond(self::request('/wp-login.php', $host));
        self::assertNotNull($served);
        self::assertStringContainsString('<form', $served->body, 'the failing bundle is skipped for the good one');
        self::assertSame(self::bodyAndType($served), self::bodyAndType($engine->respond(self::request('/wp-login.php', $host))));

        $routes['GET /wp-login.php'][RichBundleStamp::KEY] = [0];
        $allFail = self::fixtureEngine($routes)->respond(self::request('/wp-login.php', $host));
        self::assertNotNull($allFail);
        self::assertStringContainsString('zz-fixture-stub-zz', $allFail->body, 'an all-fail stamp keeps today\'s pick');
    }

    public function test_a_rich_page_the_egress_screen_would_decline_never_replaces_the_stub(): void
    {
        $f = self::fixtureBundles();
        $host = self::hostPicking([$f['login'], $f['stub']], $f['stub']);
        $engine = self::fixtureEngine(['GET /wp-login.php' => ['b' => [$f['login'], $f['stub']], RichBundleStamp::KEY => [0]]]);
        $engine->setFingerprintGuardForTesting(new FingerprintGuard(['<form'], []));

        $served = $engine->respond(self::request('/wp-login.php', $host));
        self::assertNotNull($served, 'a declined rich page must not leave the visitor with nothing');
        self::assertStringContainsString('zz-fixture-stub-zz', $served->body);
    }

    public function test_root_and_non_get_keys_ignore_a_stamp(): void
    {
        $f = self::fixtureBundles();
        $config = self::config();
        $engine = self::fixtureEngine([
            'GET /' => ['b' => [$f['login'], $f['stub']], RichBundleStamp::KEY => [0]],
            'POST /wp-login.php' => ['b' => [$f['login'], $f['stub']], RichBundleStamp::KEY => [0]],
        ]);
        $host = self::hostPicking([$f['login'], $f['stub']], $f['stub']);
        $seed = $config->seedFor(self::request('/wp-login.php', $host));

        foreach (['GET /', 'POST /wp-login.php'] as $key) {
            $served = $engine->synthesizeFromHandle(FakeHandle::route($key), SiteProfile::empty(), $seed);
            self::assertNotNull($served, $key);
            self::assertStringContainsString('zz-fixture-stub-zz', $served->body, "{$key} keeps today's pick despite a stamp");
        }
    }
}
