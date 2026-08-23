<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Response\BundleValidator;
use Funnypot\Response\EmulatedContent;
use Funnypot\Response\RouteTemplateEmulator;
use Funnypot\Response\RouteTemplateSet;
use Funnypot\Response\Style;
use PHPUnit\Framework\TestCase;

/**
 * The built-in endpoint fakes are now data (compiled route templates driven by one
 * RouteTemplateEmulator). Each is proven against a REAL compiled bundle: we load the full
 * template index, pick the route/bundle the template claims, assert the route set selects
 * the expected rule, and assert its REALISTIC and TAUNT bodies satisfy that bundle's own
 * matcher constraints (via BundleValidator — the same checks nuclei applies). This is the
 * guarantee that breadth never breaks the scanner contract.
 */
final class EmulatorBreadthTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index = null;

    private function set(): RouteTemplateSet
    {
        return RouteTemplateSet::fromFile(__DIR__ . '/../resources/compiled/funnypot-routes.php');
    }

    /**
     * label => [route key, bundle index within that route, expected route-template id].
     * Every route/bundle here is a real entry in resources/compiled/nuclei-index.full.php.
     *
     * @return array<string, array{0:string,1:int,2:string}>
     */
    public static function targets(): array
    {
        return [
            'wp-config backup (aws + db keys)' => ['GET /wp-config.php-backup', 0, 'route-wp-config'],
            'phpinfo page'                     => ['GET /tool/view/phpinfo.view.php', 0, 'route-phpinfo'],
            'htpasswd'                         => ['GET /.htpasswd', 0, 'route-htpasswd'],
            'apache server-status'             => ['GET /server-status', 0, 'route-apache-server-status'],
            'apache server-info'               => ['GET /server-info', 0, 'route-apache-server-status'],
            'package.json'                     => ['GET /package.json', 0, 'route-package-json'],
            'package-lock.json'                => ['GET /package-lock.json', 0, 'route-package-json'],
            'ssh/pem private key'              => ['GET /cgi-bin/privatekey.pem', 0, 'route-ssh-private-key'],
            'sql dump / db backup'             => ['GET /install/froxlor.sql', 0, 'route-sql-dump'],
            'wp-login (registration open)'     => ['GET /wp-login.php', 1, 'route-wp-login'],
            'weblogic console login'           => ['GET /console/login/LoginForm.jsp', 0, 'route-weblogic'],
            'exchange / owa logon'             => ['GET /owa/auth/logon.aspx', 0, 'route-exchange-owa'],
            'adminer db login'                 => ['GET /adminer.php', 0, 'route-adminer'],
            'joomla administrator'             => ['GET /administrator/', 0, 'route-joomla'],
            'wordpress readme.html'            => ['GET /readme.html', 0, 'route-wp-readme'],
            'citrix gateway logon'             => ['GET /logon/LogonPoint/index.html', 0, 'route-citrix'],
            'apache directory listing'         => ['GET /backup/', 0, 'route-directory-listing'],
            'django admin login'               => ['GET /admin/login/', 1, 'route-django-admin'],

            // Config-file disclosure pack (M8) enrich rules — each dresses a bundle the corpus
            // already routes to. A SPECIFIC needle (not a broad `config`) keeps the enrich from
            // hijacking an unrelated bundle; the satisfaction asserts below are the guard that a
            // dropped bw/nf/hw would silently fall back to minimal synth.
            'application.yml enrich'           => ['GET /application.yml', 0, 'route-application-yml'],
            'settings.json enrich'             => ['GET /settings.json', 0, 'route-settings-json'],
            'web.config enrich'                => ['GET /web.config', 0, 'route-web-config'],
            'config.js firebase enrich'        => ['GET /config.js', 0, 'route-config-js-firebase'],

            // Log-file disclosure pack enrich rules — each dresses a log bundle the corpus already
            // routes to. A full-upstream-id needle keeps the enrich from hijacking an unrelated
            // bundle; the satisfaction asserts guard against a dropped bw/hw silently falling back to
            // minimal synth. /log/access.log carries BOTH the iceflow and the generic access-log-file
            // needles; the dedicated iceflow enrich (priority 290) is checked before route-access-log
            // (296), so it wins there and serves the coherent ICEFLOW VPN body (asserted below).
            'npm-debug.log enrich'             => ['GET /npm-debug.log', 0, 'route-npm-debug-log'],
            'laravel.log enrich'               => ['GET /storage/logs/laravel.log', 0, 'route-laravel-log-file'],
            'firebase-debug.log enrich'        => ['GET /firebase-debug.log', 0, 'route-firebase-debug-log'],
            'magento debug.log enrich'         => ['GET /var/log/debug.log', 0, 'route-magento-debug-log'],
            'rails development.log enrich'     => ['GET /development.log', 0, 'route-rails-development-log'],
            'rails production.log enrich'      => ['GET /production.log', 0, 'route-rails-production-log'],
            'access.log enrich'                => ['GET /access.log', 0, 'route-access-log'],
            'iceflow /log/access.log enrich'   => ['GET /log/access.log', 0, 'route-iceflow-vpn-log'],
            'iceflow /log/vpn.log enrich'      => ['GET /log/vpn.log', 0, 'route-iceflow-vpn-log'],

            // Framework debug-page disclosure pack enrich rules — each dresses a corpus-routed
            // detection endpoint (Ignition / Symfony profiler / Werkzeug console / Spring actuator /
            // Telescope) with a specific full-upstream-id needle. The satisfaction asserts guard
            // against a dropped bw/hw silently falling back to minimal synth. /console carries THREE
            // co-bundles; the werkzeug enrich targets bundle index 2 (websphere=0, selenium=1). The
            // Ignition logs page is omitted here: its `{"log_messages"` body word pins the opening
            // brace, so it carries no JSON `_comment` taunt and is covered by NewPageRoutingTest.
            'ignition health-check enrich'     => ['GET /_ignition/health-check', 0, 'route-ignition-health-check'],
            'symfony profiler enrich'          => ['GET /_profiler/empty/search/results', 0, 'route-symfony-profiler'],
            'werkzeug console enrich'          => ['GET /console', 2, 'route-werkzeug-console'],
            'laravel telescope enrich'         => ['GET /telescope/requests', 0, 'route-telescope'],
            'actuator /env enrich'             => ['GET /actuator/env', 0, 'route-actuator-env'],
            'actuator /health enrich'          => ['GET /actuator/health', 0, 'route-actuator-health'],
            'actuator /mappings enrich'        => ['GET /actuator/mappings', 0, 'route-actuator-mappings'],
            'actuator /info enrich'            => ['GET /actuator/info', 0, 'route-actuator-info'],
            'actuator /beans enrich'           => ['GET /actuator/beans', 0, 'route-actuator-beans'],
            'actuator /loggers enrich'         => ['GET /actuator/loggers', 0, 'route-actuator-loggers'],
            'actuator /threaddump enrich'      => ['GET /actuator/threaddump', 0, 'route-actuator-threaddump'],
            'actuator /configprops enrich'     => ['GET /actuator/configprops', 0, 'route-actuator-configprops'],
        ];
    }

    /**
     * The disclosure pack's needles must each resolve to EXACTLY ONE bundle id, or the global
     * findRule would shadow an unrelated route. This is the guard behind the deliberate `/actuator`
     * index skip: `springboot-actuator` substrings `springboot-actuators-jolokia-xxe`, so it hits
     * two ids and is intentionally NOT used as a needle (the bare /actuator index is left to minimal
     * synth). Every leaf needle we DO use is asserted unique across the whole compiled index.
     */
    public function test_debug_pack_needles_are_unique_and_actuator_index_is_skipped(): void
    {
        $routes = self::index()['routes'] ?? [];
        $distinctIds = static function (string $needle) use ($routes): array {
            $ids = [];
            foreach ($routes as $entry) {
                foreach ((array) ($entry['b'] ?? []) as $b) {
                    if ((string) ($b['pid'] ?? '') === $needle) {
                        $ids[$needle . ' (pid)'] = true;
                    }
                    foreach (array_map('strval', (array) ($b['t'] ?? [])) as $id) {
                        if (strpos($id, $needle) !== false) {
                            $ids[$id] = true;
                        }
                    }
                }
            }

            return array_keys($ids);
        };

        $needles = [
            'laravel-debug-enabled', 'laravel-ignition-log-viewer', 'symfony-profiler',
            'werkzeug-debugger-detect', 'laravel-telescope', 'springboot-env', 'springboot-health',
            'springboot-mappings', 'springboot-info', 'springboot-beans', 'springboot-loggers',
            'springboot-threaddump', 'springboot-configprops',
        ];
        foreach ($needles as $needle) {
            self::assertCount(1, $distinctIds($needle), "needle '{$needle}' must resolve to exactly one bundle id (else findRule shadows another route)");
        }

        // The collision the pack avoids: `springboot-actuator` is a substring of the jolokia-xxe id,
        // so it hits >1 id and must NOT be used as an enrich needle. No shipped route template does.
        self::assertGreaterThan(1, count($distinctIds('springboot-actuator')), 'springboot-actuator must hit >1 id (this is why /actuator index is not enriched)');
        $set = $this->set();
        foreach ((require __DIR__ . '/../resources/compiled/funnypot-routes.php') as $rule) {
            foreach ((array) ($rule['match']['template_needle'] ?? []) as $n) {
                self::assertNotSame('springboot-actuator', (string) $n, "route template {$rule['id']} must not use the colliding springboot-actuator needle");
            }
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_route_set_selects_the_expected_template(string $route, int $i, string $id): void
    {
        $rule = $this->set()->findRule($this->bundle($route, $i));

        self::assertNotNull($rule, "{$route} #{$i} must select a route template");
        self::assertSame($id, $rule['id'], "{$route} #{$i} must be served by {$id}");
    }

    /**
     * A spread of persona seeds, so satisfaction is proven across the pick space — not at one
     * lucky literal. A dictionary-entry or alphabet regression that breaks only some seeds (e.g. a
     * value that displaces a required body word) surfaces here where a single fixed seed would miss it.
     *
     * @return int[]
     */
    private static function seeds(): array
    {
        $seeds = [0, 1, 2, 3, 7, 42, 777, 4242, 99999, 123456, 2020202];
        for ($s = 10; $s <= 60; $s += 3) {
            $seeds[] = $s;
        }

        return $seeds;
    }

    /**
     * @dataProvider targets
     */
    public function test_realistic_body_satisfies_the_real_bundle(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        foreach (self::seeds() as $seed) {
            $content = $emulator->render($bundle, Style::REALISTIC, $seed);
            self::assertNotNull($content, "{$route} realistic render must not decline its own bundle (seed {$seed})");
            self::assertTrue(
                BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
                "{$route} realistic body must satisfy the compiled matcher (seed {$seed})"
            );
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_taunt_body_satisfies_and_carries_the_marker(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        foreach (self::seeds() as $seed) {
            $content = $emulator->render($bundle, Style::TAUNT, $seed);
            self::assertNotNull($content, "{$route} taunt render must not decline its own bundle (seed {$seed})");
            self::assertTrue(
                BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
                "{$route} taunt body must still satisfy the compiled matcher (seed {$seed})"
            );
            self::assertStringContainsStringIgnoringCase('nice try', $content->body, "{$route} taunt must carry the marker (seed {$seed})");
        }
    }

    /**
     * @dataProvider targets
     */
    public function test_output_is_byte_identical_per_seed(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        $a = $emulator->render($bundle, Style::REALISTIC, 777);
        $b = $emulator->render($bundle, Style::REALISTIC, 777);
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, "{$route} must render identically for a fixed seed");
    }

    public function test_config_js_bundles_resolve_to_coherent_rules(): void
    {
        // The /config.js corpus route carries TWO bundles: a Firebase config (b0) and a React
        // runtime-env (b1). A broad `env-` needle on route-dotenv used to substring-hijack b1
        // (reactapp-env-js) and dress the JS endpoint as a Laravel .env. Assert each bundle now
        // resolves to its own coherent rule — b1 must be route-react-runtime-env, never route-dotenv.
        $set = $this->set();
        $r0 = $set->findRule($this->bundle('GET /config.js', 0));
        $r1 = $set->findRule($this->bundle('GET /config.js', 1));
        self::assertNotNull($r0, 'config.js firebase bundle must select a rule');
        self::assertNotNull($r1, 'config.js react runtime-env bundle must select a rule');
        self::assertSame('route-config-js-firebase', $r0['id']);
        self::assertSame('route-react-runtime-env', $r1['id'], 'react bundle must NOT resolve to route-dotenv');
        // Neither rule may dress this .js endpoint as a Laravel .env (the hijack tell).
        self::assertStringNotContainsString('APP_DEBUG=', (string) $r0['body']);
        self::assertStringNotContainsString('APP_DEBUG=', (string) $r1['body']);
    }

    /**
     * @return array<string,mixed> a single compiled bundle
     */
    private function bundle(string $route, int $i): array
    {
        $routes = self::index()['routes'] ?? [];
        self::assertArrayHasKey($route, $routes, "route {$route} is not in the compiled index");
        self::assertArrayHasKey($i, $routes[$route]['b'] ?? [], "bundle #{$i} is not present at {$route}");

        return $routes[$route]['b'][$i];
    }

    /**
     * Header set the way the synthesizer assembles it: the bundle's base headers with the
     * emulator's overrides on top. BundleValidator builds the header block from this.
     *
     * @param array<string,mixed> $bundle
     * @return array<string,string>
     */
    private function headers(array $bundle, EmulatedContent $content): array
    {
        $headers = [];
        foreach ((array) ($bundle['h'] ?? []) as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }
        foreach ($content->headers as $name => $value) {
            $headers[(string) $name] = (string) $value;
        }

        return $headers;
    }

    /**
     * @return array<string,mixed>
     */
    private static function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }
}
