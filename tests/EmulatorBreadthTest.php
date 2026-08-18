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
    private static ?array $index = null;

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
        ];
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
     * @dataProvider targets
     */
    public function test_realistic_body_satisfies_the_real_bundle(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        $content = $emulator->render($bundle, Style::REALISTIC, 4242);
        self::assertNotNull($content, "{$route} realistic render must not decline its own bundle");
        self::assertTrue(
            BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
            "{$route} realistic body must satisfy the compiled matcher"
        );
    }

    /**
     * @dataProvider targets
     */
    public function test_taunt_body_satisfies_and_carries_the_marker(string $route, int $i, string $id): void
    {
        $bundle = $this->bundle($route, $i);
        $emulator = new RouteTemplateEmulator($this->set());

        $content = $emulator->render($bundle, Style::TAUNT, 4242);
        self::assertNotNull($content);
        self::assertTrue(
            BundleValidator::satisfies($content->body, $this->headers($bundle, $content), $bundle),
            "{$route} taunt body must still satisfy the compiled matcher"
        );
        self::assertStringContainsStringIgnoringCase('nice try', $content->body, "{$route} taunt must carry the marker");
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
