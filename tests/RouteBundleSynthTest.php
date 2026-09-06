<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\RouteBundleSynth;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The synth enforces the reserved `route-` id prefix on every new_page (RouteIndexFold owns the
 * index by that prefix) and emits a fragment of exactly {templates, routes} — the only shape the
 * rules updater walks when it re-`require`s funnypot-routes-index.php.
 */
final class RouteBundleSynthTest extends TestCase
{
    /** @var string */
    private $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/fp-synth-' . getmypid() . '-' . uniqid();
        if (!mkdir($this->dir, 0775, true) && !is_dir($this->dir)) {
            self::fail("cannot create temp dir {$this->dir}");
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

    public function test_new_page_id_outside_the_reserved_prefix_is_rejected(): void
    {
        $this->write('bad', <<<'YAML'
id: npmrc-page
new_page:
  method: GET
  paths:
    - /npmrc-page
  name: Bad id
YAML);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/route-\[a-z0-9-\]\+/');
        (new RouteBundleSynth())->fragment($this->dir);
    }

    public function test_route_prefixed_id_yields_a_two_key_fragment(): void
    {
        $this->write('ok', <<<'YAML'
id: route-ok
new_page:
  method: GET
  paths:
    - /route-ok
  name: Route OK
YAML);

        $fragment = (new RouteBundleSynth())->fragment($this->dir);

        self::assertSame(['templates', 'routes'], array_keys($fragment), 'fragment top-level shape is the updater contract');
        self::assertSame(['route-ok'], array_keys($fragment['templates']));
        self::assertArrayHasKey('GET /route-ok', $fragment['routes']);
        self::assertSame('route-ok', $fragment['routes']['GET /route-ok'][0]['pid']);
    }

    public function test_new_page_serving_a_detector_signature_in_body_words_is_a_build_failure(): void
    {
        // A hand-authored bundle that serves an upstream-detector signature is a build failure, not a
        // fold — the author must fix the source (FP-0262).
        $this->write('leak', <<<'YAML'
id: route-leak
new_page:
  method: GET
  paths:
    - /route-leak
  name: Leaky page
  body_words:
    - "blocked by OWASP_CRS ruleset"
YAML);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/route-leak.*(body_words|typed_headers)/');
        (new RouteBundleSynth())->fragment($this->dir);
    }

    public function test_new_page_serving_a_signature_in_a_typed_header_is_a_build_failure(): void
    {
        $this->write('th', <<<'YAML'
id: route-th-leak
new_page:
  method: GET
  paths:
    - /route-th-leak
  name: Leaky typed header
  typed_headers:
    Location:
      - "https://interact.sh"
YAML);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/route-th-leak/');
        (new RouteBundleSynth())->fragment($this->dir);
    }
}
