<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\Classifier;
use Funnypot\Compiler\ClusterableFilter;
use Funnypot\Compiler\TemplateLoader;
use PHPUnit\Framework\TestCase;

/**
 * Gate A / Gate B classifier behavior, exercised on hand-built templates that isolate
 * each mandatory review screen (A1/A2/B6) and the eligibility filter.
 */
final class ClassifierTest extends TestCase
{
    private TemplateLoader $loader;
    private ClusterableFilter $gateA;
    private Classifier $gateB;

    protected function setUp(): void
    {
        $this->loader = new TemplateLoader();
        $this->gateA = new ClusterableFilter();
        $this->gateB = new Classifier();
    }

    /** @param array<string,mixed> $doc */
    private function load(array $doc): \Funnypot\Compiler\LoadedTemplate
    {
        // rawText matters for the interactsh scan; serialize a rough approximation.
        return $this->loader->fromArray($doc, json_encode($doc) ?: '', '/virtual/' . ($doc['id'] ?? 'x') . '.yaml');
    }

    /** @param array<string,mixed> $doc */
    private function classify(array $doc)
    {
        return $this->gateB->classify($this->load($doc));
    }

    // ---- A2: dynamic {{...}} literals ----

    public function test_randstr_word_under_and_folds_template_out(): void
    {
        $doc = [
            'id' => 'dyn-randstr',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/probe'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['{{randstr}}']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'A2: an unresolvable {{randstr}} word must fold the AND template OUT');
        self::assertSame('word-dynamic-literal', $c->reason);
    }

    public function test_md5_word_is_unresolvable_and_folds_out(): void
    {
        $doc = [
            'id' => 'dyn-md5',
            'info' => ['severity' => 'info', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['{{md5(123)}}']],
                ],
            ]],
        ];

        self::assertFalse($this->classify($doc)->in);
    }

    public function test_hostname_word_is_resolvable_and_kept(): void
    {
        $doc = [
            'id' => 'dyn-hostname',
            'info' => ['severity' => 'info', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['welcome {{Hostname}}']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, '{{Hostname}} is synth-resolvable and must not fold the template');
        self::assertContains('welcome {{Hostname}}', $c->plan->bodyWords);
    }

    // ---- A1: anchored regex is whole-body-exclusive ----

    public function test_anchored_regex_is_whole_body_exclusive(): void
    {
        $doc = [
            'id' => 'anchored-rx',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'regex', 'part' => 'body', 'regex' => ['^[a-z]+$']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a simple anchored regex should still invert');
        self::assertTrue($c->plan->wholeBodyExclusive, 'A1: ^...$ must flag whole-body-exclusive');
        self::assertNotEmpty($c->plan->regexWitness);
    }

    public function test_unanchored_regex_is_not_exclusive(): void
    {
        $doc = [
            'id' => 'plain-rx',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'regex', 'part' => 'body', 'regex' => ['token=[0-9]{3}']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertFalse($c->plan->wholeBodyExclusive);
    }

    // ---- Gate A exclusions ----

    public function test_variable_path_payload_template_is_still_excluded(): void
    {
        // R4 (deferred): a payload BUILDS the request path, so it can never be pinned to a
        // compile-time route key — it must still fold, now at the variable-path screen.
        $doc = [
            'id' => 'has-payloads',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/{{path}}'],
                'payloads' => ['path' => ['a', 'b']],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:variable-path', $this->gateA->reject($this->load($doc)));
    }

    public function test_payloads_literal_path_template_is_admitted(): void
    {
        // R3: the payloads only fill the request body/query; the path is a literal, so the
        // template compiles on its fixed path + static matchers, ignoring the payloads.
        $doc = [
            'id' => 'esafenet-like',
            'info' => ['severity' => 'high', 'tags' => 'default-login'],
            'http' => [[
                'method' => 'POST',
                'path' => ['{{BaseURL}}/CDGServer3/SystemConfig'],
                'body' => 'name={{username}}&pass={{password}}',
                'payloads' => ['username' => ['admin'], 'password' => ['x']],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['est.connection.url']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        self::assertNull($this->gateA->reject($this->load($doc)), 'literal-path payload template must pass Gate A');
        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a literal-path payload template must classify IN');
        self::assertSame(200, $c->plan->status);
        self::assertContains('est.connection.url', $c->plan->bodyWords);
    }

    public function test_single_request_raw_template_is_admitted(): void
    {
        // R2: the raw request line pins METHOD + literal path; matchers invert normally.
        $doc = [
            'id' => 'raw-post',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'raw' => ["POST /api/login HTTP/1.1\nHost: {{Hostname}}\n\nu=a&p=b"],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['authToken']],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $loaded = $this->load($doc);
        self::assertSame('POST', $loaded->method, 'method is lifted from the raw request line');
        self::assertSame(['{{BaseURL}}/api/login'], $loaded->paths, 'path is lifted from the raw request line');
        self::assertNull($this->gateA->reject($loaded), 'single-request raw must pass Gate A');

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a single-request raw template must classify IN');
        self::assertContains('authToken', $c->plan->bodyWords);
    }

    public function test_bare_path_raw_request_gets_baseurl_prefixed(): void
    {
        // A raw target is host-relative ("/x"); it is rewritten to {{BaseURL}}/x so route
        // keys agree byte-for-byte with a path template's.
        $doc = [
            'id' => 'raw-get',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'raw' => ["GET /solr/admin/cores?wt=json HTTP/1.1\nHost: {{Hostname}}"],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        $loaded = $this->load($doc);
        self::assertSame('GET', $loaded->method);
        self::assertSame(['{{BaseURL}}/solr/admin/cores?wt=json'], $loaded->paths);
        self::assertNull($this->gateA->reject($loaded));
    }

    public function test_raw_request_annotation_line_is_skipped(): void
    {
        // Nuclei raw annotations (@timeout, @tls-sni, …) precede the request line; the
        // parser must step over them to find "METHOD target HTTP/x".
        $doc = [
            'id' => 'raw-annotated',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'raw' => ["@timeout 10s\nGET /wp-admin/admin-ajax.php?id=1 HTTP/1.1\nHost: {{Hostname}}"],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        $loaded = $this->load($doc);
        self::assertSame('GET', $loaded->method);
        self::assertSame(['{{BaseURL}}/wp-admin/admin-ajax.php?id=1'], $loaded->paths);
        self::assertNull($this->gateA->reject($loaded));
    }

    public function test_multi_request_raw_template_is_excluded(): void
    {
        // Two raw requests are a flow: only the first is routed, so later-step matchers
        // could never be satisfied. Stays excluded.
        $doc = [
            'id' => 'raw-multi',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'raw' => [
                    "GET /step1 HTTP/1.1\nHost: {{Hostname}}",
                    "GET /step2 HTTP/1.1\nHost: {{Hostname}}",
                ],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:multi-raw', $this->gateA->reject($this->load($doc)));
    }

    public function test_variable_path_raw_template_is_excluded(): void
    {
        // A raw target carrying an unresolved {{...}} in the path itself cannot be pinned.
        $doc = [
            'id' => 'raw-var',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'raw' => ["GET /{{core}}/select HTTP/1.1\nHost: {{Hostname}}"],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:variable-path', $this->gateA->reject($this->load($doc)));
    }

    public function test_interactsh_template_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'has-oob',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x?u={{interactsh-url}}'],
                'matchers' => [
                    ['type' => 'word', 'part' => 'interactsh_protocol', 'words' => ['dns']],
                ],
            ]],
        ];

        self::assertSame('gateA:interactsh-oob', $this->gateA->reject($this->load($doc)));
    }

    public function test_external_host_path_is_gate_a_excluded(): void
    {
        $doc = [
            'id' => 'osint',
            'info' => ['severity' => 'info', 'tags' => 'osint'],
            'http' => [[
                'method' => 'GET',
                'path' => ['https://example.com/{{user}}'],
                'matchers' => [['type' => 'status', 'status' => [200]]],
            ]],
        ];

        self::assertSame('gateA:non-baseurl-path', $this->gateA->reject($this->load($doc)));
    }

    // ---- IN: pure status + word(body) ----

    public function test_status_plus_body_word_is_in_with_plan(): void
    {
        // Mirrors git-config: word(body, or) + dsl !contains + status, all under AND.
        $doc = [
            'id' => 'git-config',
            'info' => ['severity' => 'medium', 'tags' => 'config,git,exposure'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/.git/config'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['[credentials]', '[core]'], 'condition' => 'or'],
                    ['type' => 'dsl', 'condition' => 'and', 'dsl' => [
                        "!contains(tolower(body), '<html')",
                        "!contains(tolower(body), '<body')",
                    ]],
                    ['type' => 'status', 'status' => [200]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in, 'a clean status+word(body) template must be IN');
        self::assertSame(200, $c->plan->status);
        // OR word matcher contributes exactly one required body word.
        self::assertContains('[credentials]', $c->plan->bodyWords);
        self::assertCount(1, $c->plan->bodyWords);
        // The dsl !contains clauses become forbidden body substrings.
        self::assertContains('<html', $c->plan->forbidden);
        self::assertContains('<body', $c->plan->forbidden);
        self::assertSame('git', $c->plan->product, 'pid falls back to the git tag');
    }

    public function test_dsl_status_and_contains_conjunction_is_in(): void
    {
        $doc = [
            'id' => 'dsl-conj',
            'info' => ['severity' => 'medium', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/pkg'],
                'matchers' => [
                    ['type' => 'dsl', 'dsl' => [
                        "contains(body, 'packages') && status_code == 200",
                    ]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertTrue($c->in);
        self::assertSame(200, $c->plan->status);
        self::assertContains('packages', $c->plan->bodyWords);
    }

    // ---- B6: intra-template satisfiability ----

    public function test_contradictory_status_folds_out_b6(): void
    {
        $doc = [
            'id' => 'b6-status',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'status', 'status' => [200]],
                    ['type' => 'dsl', 'dsl' => ['status_code == 404']],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'B6: status 200 AND status_code==404 is unsatisfiable');
        self::assertStringContainsString('status-contradiction', $c->reason);
    }

    public function test_required_and_forbidden_same_word_folds_out_b6(): void
    {
        $doc = [
            'id' => 'b6-word',
            'info' => ['severity' => 'low', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers-condition' => 'and',
                'matchers' => [
                    ['type' => 'word', 'part' => 'body', 'words' => ['ADMIN']],
                    ['type' => 'dsl', 'dsl' => ["!contains(body, 'ADMIN')"]],
                ],
            ]],
        ];

        $c = $this->classify($doc);
        self::assertFalse($c->in, 'B6: a word both required and forbidden is unsatisfiable');
        self::assertStringContainsString('contradiction', $c->reason);
    }

    // ---- unsupported dsl folds out ----

    public function test_compare_versions_dsl_folds_out(): void
    {
        $doc = [
            'id' => 'cmpver',
            'info' => ['severity' => 'high', 'tags' => 'test'],
            'http' => [[
                'method' => 'GET',
                'path' => ['{{BaseURL}}/x'],
                'matchers' => [
                    ['type' => 'dsl', 'dsl' => ["compare_versions(version, '< 2.0.0')"]],
                ],
            ]],
        ];

        self::assertFalse($this->classify($doc)->in);
    }
}
