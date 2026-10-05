<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0453: default-serving, request-aware GraphQL introspection + schema-fuzzing decoy
 * (attack/39-graphql-introspection). Every assertion runs at the DEFAULT `high` severity ceiling —
 * that is the point of the re-scope: route/335 is `critical` and dropped by default, so this `high`
 * attack rule is what actually serves a schema on a normal deploy. INERT: no cookie, no auth witness,
 * no reflection of attacker-submitted field names; always 200 JSON.
 */
final class GraphQlIntrospectionDecoyTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private function index(): array
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return self::$index;
    }

    /** Full engine over the real corpus at the DEFAULT `high` ceiling, respond mode, fixed seed. */
    private function engine(): Honeypot
    {
        return new Honeypot(
            new PhpArrayStore($this->index()),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'high',
                65536, 0, 0, true, null, null, null, 'fixed')
        );
    }

    private function post(string $path, string $query): ?object
    {
        return $this->engine()->respond(
            new RequestContext('POST', $path, '', ['Content-Type' => 'application/json'],
                '{"query":"' . str_replace('"', '\\"', $query) . '"}', 'x.test')
        );
    }

    public function test_akto_introspection_query_gets_data_and_schema_at_default_ceiling(): void
    {
        // Akto GraphqlIntrospectionEnabled: contains_all ["data","__schema"].
        $r = $this->post('/graphql', 'query IntrospectionQuery { __schema { queryType { name } types { kind name } } }');
        self::assertNotNull($r, 'POST /graphql introspection must serve on a default deploy');
        self::assertSame(200, $r->status);
        self::assertStringContainsString('application/json', $r->headers['Content-Type'] ?? '');
        self::assertStringContainsString('"data"', $r->body);
        self::assertStringContainsString('__schema', $r->body);
    }

    public function test_vulnapi_minimal_introspection_gets_populated_types(): void
    {
        // VulnAPI discoverable_graphql: 200 + json + populated data.__schema.types.
        $r = $this->post('/graphql', '{__schema{types{name}}}');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('"types": [', $r->body);
        self::assertStringContainsString('"name": "Query"', $r->body);
    }

    public function test_schema_is_json_parseable_and_shaped(): void
    {
        $r = $this->post('/graphql', '{__schema{types{name}}}');
        self::assertNotNull($r);
        $decoded = json_decode($r->body, true);
        self::assertIsArray($decoded, 'the introspection body must be valid JSON');
        self::assertArrayHasKey('data', $decoded);
        self::assertArrayHasKey('__schema', $decoded['data']);
        self::assertNotEmpty($decoded['data']['__schema']['types']);
    }

    public function test_bait_data_query_leaks_a_persona_honeytoken_no_cookie(): void
    {
        $r = $this->post('/graphql', 'query { viewer { email apiKey } systemConfig { awsSecretKey } }');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        // A tracked deploy-stable AWS canary (AKIA… id), coherent with /.env — never a real key.
        self::assertMatchesRegularExpression('/AKIA[0-9A-Z]{16}/', $r->body, 'a bait query leaks a synthetic AWS canary');
        self::assertArrayNotHasKey('Set-Cookie', $r->headers, 'a data query mints no session');
    }

    public function test_mutation_returns_fabricated_success_not_fabricated_auth(): void
    {
        $r = $this->post('/graphql', 'mutation { updateUserRole(userId: 1, role: \\"admin\\") { success } }');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('"success":true', $r->body);
        // Fabricated DATA is allowed; fabricated AUTH is not — no cookie, no auth-success witness line.
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
        self::assertStringNotContainsString('Location', implode(' ', array_keys($r->headers)));
    }

    public function test_unknown_field_gets_coherent_error_without_reflecting_input(): void
    {
        $r = $this->post('/graphql', 'query { secretBackdoorField_CANARY { token } }');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('GRAPHQL_VALIDATION_FAILED', $r->body);
        // No capture reflection: the attacker's submitted field name is never echoed back.
        self::assertStringNotContainsString('secretBackdoorField_CANARY', $r->body,
            'the submitted field name must not be reflected');
    }

    public function test_get_introspection_is_handled(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/graphql',
            'query=' . rawurlencode('{__schema{types{name}}}'), [], null, 'x.test'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertStringContainsString('__schema', $r->body);
    }

    public function test_bare_get_without_query_falls_through_to_inert_envelope(): void
    {
        // The match gate requires a graphql operation token, so a bare GET falls through byte-identically
        // to route/404-graphql-get (the inert "must be sent as POST" envelope) — not a schema leak.
        $r = $this->engine()->respond(new RequestContext('GET', '/graphql', '', [], null, 'x.test'));
        self::assertNotNull($r);
        self::assertStringNotContainsString('__schema', $r->body, 'a bare probe must not leak the schema');
        self::assertStringContainsString('POST', $r->body);
    }

    /**
     * @dataProvider endpointAliases
     */
    public function test_endpoint_aliases_all_serve_the_schema(string $path): void
    {
        $r = $this->post($path, '{__schema{types{name}}}');
        self::assertNotNull($r, "{$path} must own the graphql surface");
        self::assertStringContainsString('__schema', $r->body);
    }

    /** @return array<string,array{0:string}> */
    public function endpointAliases(): array
    {
        return [
            'root' => ['/graphql'],
            'api'  => ['/api/graphql'],
            'v1'   => ['/v1/graphql'],
        ];
    }
}
