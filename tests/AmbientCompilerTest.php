<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\AmbientPaths;
use Funnypot\Core\Compiler\Compiler;
use Funnypot\Core\Compiler\RouteBundleSynth;
use PHPUnit\Framework\TestCase;

/**
 * Mechanism proof for the amb=1 stamp on BOTH halves of the build (FP-0087), independent of the
 * real corpus and the real resources/ambient-paths.php. CompiledIndexSmokeTest covers the real
 * artifact; this covers the compiler and the fragment synth against injected lists.
 */
final class AmbientCompilerTest extends TestCase
{
    /** @var string */
    private $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/funnypot-ambient-' . getmypid() . '-' . uniqid();
        if (!mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
            self::fail("cannot create temp corpus dir {$this->dir}");
        }
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*.yaml') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private function write(string $name, string $yaml): void
    {
        file_put_contents($this->dir . '/' . $name . '.yaml', $yaml);
    }

    /** A minimal nuclei template routing METHOD path with a word+status matcher (POST carries a form body). */
    private function template(string $id, string $path, string $method = 'GET'): string
    {
        $body = $method === 'GET' ? '' : "\n        Content-Type: application/x-www-form-urlencoded\n\n        a=b";

        return <<<YAML
id: {$id}
info:
  name: {$id}
  severity: info
  tags: test
http:
  - raw:
      - |
        {$method} {$path} HTTP/1.1
        Host: {{Hostname}}{$body}
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "irrelevant-marker"
      - type: status
        status:
          - 200
YAML;
    }

    /** A minimal route template with a new_page block (the RouteBundleSynth input shape). */
    private function newPage(string $id, string $pathsYaml, string $extra = ''): string
    {
        return "id: {$id}\nnew_page:\n  method: GET\n  paths: {$pathsYaml}\n  sig: 0\n  status: 200\n"
            . "  name: '{$id}'\n{$extra}";
    }

    // --- corpus half: Compiler ---------------------------------------------------------------

    public function test_a_path_on_the_ambient_list_is_stamped(): void
    {
        $this->write('t1', $this->template('t-favicon', '/favicon.ico'));

        $routes = (new Compiler())->compile($this->dir, [], ['/favicon.ico'])['index']['routes'];

        self::assertSame(1, $routes['GET /favicon.ico']['b'][0]['amb']);
    }

    public function test_a_path_not_on_the_ambient_list_is_not_stamped(): void
    {
        $this->write('t1', $this->template('t-env', '/.env'));

        $routes = (new Compiler())->compile($this->dir, [], ['/favicon.ico'])['index']['routes'];

        self::assertSame(0, $routes['GET /.env']['b'][0]['amb']);
    }

    public function test_a_subpath_is_never_matched_by_a_prefix_rule(): void
    {
        $this->write('t1', $this->template('t-actuator', '/actuator/favicon.ico'));

        $routes = (new Compiler())->compile($this->dir, [], ['/favicon.ico'])['index']['routes'];

        self::assertSame(0, $routes['GET /actuator/favicon.ico']['b'][0]['amb']);
    }

    public function test_ambient_stamp_is_method_scoped_to_get(): void
    {
        $this->write('t1', $this->template('t-robots-post', '/robots.txt', 'POST'));

        $routes = (new Compiler())->compile($this->dir, [], ['/robots.txt'])['index']['routes'];

        self::assertSame(0, $routes['POST /robots.txt']['b'][0]['amb'], 'POST must not inherit the GET-scoped stamp');
    }

    public function test_route_keys_are_exact_get_keys(): void
    {
        self::assertSame(
            ['GET /favicon.ico' => true, 'GET /.well-known/security.txt' => true],
            AmbientPaths::routeKeys(['/favicon.ico', '/.well-known/security.txt'])
        );
    }

    // --- fold half: RouteBundleSynth ---------------------------------------------------------

    public function test_fragment_stamps_per_path_not_per_template(): void
    {
        // The real 393-sitemap-xml.yaml shape: one new_page, three paths, two of them curated.
        $this->write('r1', $this->newPage('route-sitemap', "['/sitemap.xml', '/sitemap', '/sitemap_index.xml']"));

        $routes = (new RouteBundleSynth(['/sitemap.xml', '/sitemap_index.xml']))->fragment($this->dir)['routes'];

        self::assertSame(1, $routes['GET /sitemap.xml'][0]['amb']);
        self::assertSame(1, $routes['GET /sitemap_index.xml'][0]['amb']);
        self::assertSame(0, $routes['GET /sitemap'][0]['amb'], 'an uncurated path in the same new_page must not be stamped');
    }

    public function test_fragment_ignores_a_template_level_amb_key(): void
    {
        // There is no per-template knob: a YAML `amb: 1` on an uncurated path must not stamp it.
        $this->write('r1', $this->newPage('route-x', "['/not-curated']", "  amb: 1\n"));

        $routes = (new RouteBundleSynth(['/favicon.ico']))->fragment($this->dir)['routes'];

        self::assertSame(0, $routes['GET /not-curated'][0]['amb']);
    }

    public function test_fragment_keeps_the_optional_bundle_keys_alongside_amb(): void
    {
        // Regression guard for the per-path copy: weight and bin still ride on every path's bundle.
        $this->write('r1', $this->newPage('route-fav', "['/favicon.ico', '/x/favicon.ico']", "  weight: 20\nresponse:\n  headers: { Content-Type: 'image/x-icon' }\n  body_b64: 'aWNvbg=='\n"));

        $routes = (new RouteBundleSynth(['/favicon.ico']))->fragment($this->dir)['routes'];

        foreach (['GET /favicon.ico' => 1, 'GET /x/favicon.ico' => 0] as $key => $amb) {
            self::assertSame($amb, $routes[$key][0]['amb'], $key);
            self::assertSame(20, $routes[$key][0]['w'], $key);
            self::assertSame(1, $routes[$key][0]['bin'], $key);
        }
    }

    public function test_package_list_loads_and_is_the_curated_set(): void
    {
        $paths = AmbientPaths::fromPackage();

        self::assertContains('/favicon.ico', $paths);
        self::assertContains('/sitemap_index.xml', $paths);
        self::assertNotContains('/sitemap', $paths);
        self::assertNotContains('/.well-known/openid-configuration', $paths);
        self::assertNotContains('/crossdomain.xml', $paths);
    }
}
