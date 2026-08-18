<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Compiler;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end compile of a tiny on-disk corpus, asserting the raw / payload-literal
 * admission classes (R2/R3) reach the schema-1 route table under their REAL method —
 * the index is no longer GET-only.
 */
final class CompilerAdmissionTest extends TestCase
{
    private string $dir = '';

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
