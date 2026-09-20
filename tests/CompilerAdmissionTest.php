<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Compiler;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end compile of a tiny on-disk corpus, asserting the raw / payload-literal
 * admission classes (R2/R3) reach the schema-1 route table under their REAL method —
 * the index is no longer GET-only.
 */
final class CompilerAdmissionTest extends TestCase
{
    /** @var string */
    private $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/funnypot-admit-' . getmypid() . '-' . uniqid();
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

    /** @return array<string,mixed> */
    private function compile(): array
    {
        return (new Compiler())->compile($this->dir);
    }

    public function test_raw_template_compiles_to_post_route_with_matcher(): void
    {
        $this->write('raw-post', <<<'YAML'
id: raw-post-login
info:
  name: Raw POST login
  severity: high
  tags: test
http:
  - raw:
      - |
        POST /api/session HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        user=admin&pass=admin
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "sessionToken"
      - type: status
        status:
          - 200
YAML);

        $routes = $this->compile()['index']['routes'];

        self::assertArrayHasKey('POST /api/session', $routes, 'raw template must emit a POST route key');
        self::assertArrayNotHasKey('GET /api/session', $routes, 'the raw method is POST, not GET');

        $bundle = $routes['POST /api/session']['b'][0];
        self::assertSame(200, $bundle['s']);
        self::assertContains('sessionToken', $bundle['bw']);
        self::assertContains('raw-post-login', $bundle['t']);
    }

    public function test_payload_literal_path_compiles_under_its_method(): void
    {
        $this->write('payload-post', <<<'YAML'
id: payload-default-login
info:
  name: Payload default login
  severity: high
  tags: default-login
http:
  - method: POST
    path:
      - "{{BaseURL}}/admin/SystemConfig"
    headers:
      content-type: application/x-www-form-urlencoded
    body: "name={{username}}&pass={{password}}"
    attack: clusterbomb
    payloads:
      username:
        - admin
      password:
        - secret
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "connection.url"
      - type: status
        status:
          - 200
YAML);

        $routes = $this->compile()['index']['routes'];

        self::assertArrayHasKey('POST /admin/SystemConfig', $routes);
        $bundle = $routes['POST /admin/SystemConfig']['b'][0];
        self::assertContains('connection.url', $bundle['bw']);
        self::assertContains('payload-default-login', $bundle['t']);
    }

    public function test_variable_path_payload_is_not_routed(): void
    {
        $this->write('payload-fuzz', <<<'YAML'
id: payload-path-fuzz
info:
  name: Payload path fuzz
  severity: high
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/{{fuzz}}"
    payloads:
      fuzz:
        - a
        - b
    matchers:
      - type: status
        status:
          - 200
YAML);

        $result = $this->compile();
        self::assertSame([], $result['index']['routes'], 'a payload-built path must not be routed (R4 deferred)');
        self::assertSame('gateA:variable-path', $result['skipped']['payload-path-fuzz'] ?? null);
    }

    public function test_corpus_template_squatting_the_reserved_route_prefix_is_skipped(): void
    {
        // The route- id prefix is reserved for the folded new_page set. A corpus template that uses
        // it must be skipped with a recorded reason, never admitted (the next fold would delete it).
        $this->write('route-shadow', <<<'YAML'
id: route-shadow
info:
  name: Shadow
  severity: high
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/route-shadow"
    matchers:
      - type: status
        status:
          - 200
YAML);

        $result = $this->compile();
        self::assertSame('gateA:reserved-route-id', $result['skipped']['route-shadow'] ?? null);
        self::assertArrayNotHasKey('route-shadow', $result['index']['templates']);
        self::assertSame([], $result['index']['routes'], 'a reserved-prefix corpus template must not route');
    }

    // --- FP-0280: frozen per-deploy regex-witness menu (rxm) --------------------------------------

    public function test_regex_bundle_freezes_a_sparse_alternates_only_menu(): void
    {
        $this->write('rxm-basic', <<<'YAML'
id: fp0280-basic
info:
  name: rxm basic
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/fp0280-basic"
    matchers:
      - type: regex
        part: body
        regex:
          - "token=[0-9]{3}"
YAML);

        $bundle = $this->compile()['index']['routes']['GET /fp0280-basic']['b'][0];
        self::assertSame(['token=000'], $bundle['rx'], 'the canonical rx is unchanged');
        self::assertArrayHasKey('rxm', $bundle, 'a witnessable pattern freezes a menu');
        self::assertArrayHasKey(0, $bundle['rxm'], 'rxm is keyed by the rx index');
        foreach ($bundle['rxm'][0] as $alt) {
            self::assertNotSame('token=000', $alt, 'the canonical is never in the menu (alternates-only)');
            self::assertSame(1, preg_match('~token=[0-9]{3}~', $alt), "alternate must satisfy the pattern: {$alt}");
        }
    }

    public function test_shared_canonical_across_templates_intersects_the_menu(): void
    {
        // x[a-c]y and x[a-b]y both collapse to canonical 'xay' on one route but generate different
        // alternates; the frozen menu is their intersection, so it satisfies BOTH source patterns.
        $this->write('rxm-shared-a', <<<'YAML'
id: fp0280-shared-a
info: {name: A, severity: info, tags: test}
http:
  - method: GET
    path: ["{{BaseURL}}/fp0280-shared"]
    matchers:
      - {type: regex, part: body, regex: ["x[a-c]y"]}
YAML);
        $this->write('rxm-shared-b', <<<'YAML'
id: fp0280-shared-b
info: {name: B, severity: info, tags: test}
http:
  - method: GET
    path: ["{{BaseURL}}/fp0280-shared"]
    matchers:
      - {type: regex, part: body, regex: ["x[a-b]y"]}
YAML);

        $bundle = $this->compile()['index']['routes']['GET /fp0280-shared']['b'][0];
        self::assertSame(['xay'], $bundle['rx']);
        self::assertSame([0 => ['xby']], $bundle['rxm'], 'only the shared alternate survives the intersection');
        foreach ($bundle['rxm'][0] as $alt) {
            self::assertSame(1, preg_match('~x[a-c]y~', $alt), 'alternate satisfies template A');
            self::assertSame(1, preg_match('~x[a-b]y~', $alt), 'alternate satisfies template B');
        }
    }

    public function test_forbidden_substring_alternate_is_dropped_at_freeze(): void
    {
        // The 'vzw' alternate of v[a-z]w is a forbidden substring (nf); it is filtered before freeze.
        $this->write('rxm-nf', <<<'YAML'
id: fp0280-nf
info: {name: NF, severity: info, tags: test}
http:
  - method: GET
    path: ["{{BaseURL}}/fp0280-nf"]
    matchers-condition: and
    matchers:
      - {type: regex, part: body, regex: ["v[a-z]w"]}
      - {type: dsl, dsl: ["!contains(body, 'vzw')"]}
YAML);

        $bundle = $this->compile()['index']['routes']['GET /fp0280-nf']['b'][0];
        self::assertContains('vzw', $bundle['nf']);
        self::assertArrayHasKey('rxm', $bundle);
        foreach ($bundle['rxm'][0] as $alt) {
            self::assertStringNotContainsString('vzw', $alt, 'a forbidden-substring alternate must be dropped');
        }
    }

    public function test_literal_regex_has_no_menu(): void
    {
        $this->write('rxm-literal', <<<'YAML'
id: fp0280-literal
info: {name: L, severity: info, tags: test}
http:
  - method: GET
    path: ["{{BaseURL}}/fp0280-literal"]
    matchers:
      - {type: regex, part: body, regex: ["exactliteral"]}
YAML);

        $bundle = $this->compile()['index']['routes']['GET /fp0280-literal']['b'][0];
        self::assertSame(['exactliteral'], $bundle['rx']);
        self::assertArrayNotHasKey('rxm', $bundle, 'a no-alternate pattern emits no rxm key (sparse)');
    }

    public function test_frozen_rxm_is_a_pure_literal_and_deterministic(): void
    {
        $this->write('rxm-det', <<<'YAML'
id: fp0280-det
info: {name: D, severity: info, tags: test}
http:
  - method: GET
    path: ["{{BaseURL}}/fp0280-det"]
    matchers:
      - {type: regex, part: body, regex: ["id-[A-F0-9]{4}"]}
YAML);

        $first = $this->compile()['index']['routes'];
        $second = $this->compile()['index']['routes'];
        self::assertSame($first, $second, 'two compiles of the same fixture produce identical arrays');
        array_walk_recursive($first, static function ($v): void {
            self::assertFalse(is_object($v), 'the frozen menu contains no objects/closures');
        });
    }

    public function test_method_variety_is_carried_through(): void
    {
        $this->write('put-raw', <<<'YAML'
id: raw-put
info:
  name: Raw PUT
  severity: low
  tags: test
http:
  - raw:
      - |
        PUT /upload/here HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: word
        part: body
        words:
          - "created"
YAML);

        $routes = $this->compile()['index']['routes'];
        self::assertArrayHasKey('PUT /upload/here', $routes, 'non-GET/POST raw methods must route too');
    }
}
