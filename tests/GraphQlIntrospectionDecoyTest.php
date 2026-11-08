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
 * The default-serving GraphQL decoy (attack/39-graphql-introspection) as the introspection scanners see
 * it. Every assertion runs at the DEFAULT `high` severity ceiling, where this attack rule (not the
 * `critical` route/335 bundle) serves the schema. INERT: no cookie, no auth witness, and on an embedded
 * host no attacker-submitted field name in any message.
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
            new Config('respond', static function (RequestContext $r): bool {
                return true;
            }, 'matched-only', static function (RequestContext $r): string {
                return 'fixed';
            }, 'coherent', Style::REALISTIC, 'high', 65536, 0, 0, true, null, null, null, 'fixed')
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
        $types = json_decode($r->body, true)['data']['__schema']['types'] ?? [];
        self::assertNotEmpty($types);
        self::assertContains('Query', array_column($types, 'name'));
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
        $r = $this->post('/graphql', 'query { viewer { email apiKey } systemConfig { awsAccessKeyId awsSecretKey } }');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        $data = json_decode($r->body, true)['data'];
        self::assertNull($data['viewer'], 'an anonymous viewer is null');
        // A tracked deploy-stable AWS canary (AKIA… id), coherent with /.env — never a real key.
        self::assertMatchesRegularExpression('/\AAKIA[0-9A-Z]{16}\z/', $data['systemConfig']['awsAccessKeyId'], 'the open config leaks a synthetic AWS canary');
        self::assertArrayNotHasKey('Set-Cookie', $r->headers, 'a data query mints no session');
    }

    public function test_mutation_is_refused_as_unauthenticated(): void
    {
        $r = $this->post('/graphql', 'mutation { updateUserRole(userId: 1, role: "admin") { success } }');
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        $decoded = json_decode($r->body, true);
        self::assertSame('UNAUTHENTICATED', $decoded['errors'][0]['extensions']['code']);
        self::assertNull($decoded['data']['updateUserRole']);
        self::assertStringNotContainsString('"success":true', $r->body, 'a write never claims to succeed');
        self::assertArrayNotHasKey('Set-Cookie', $r->headers);
        self::assertStringNotContainsString('Location', implode(' ', array_keys($r->headers)));
    }

    public function test_unknown_field_gets_coherent_error_without_reflecting_input(): void
    {
        $r = $this->post('/graphql', 'query { secretBackdoorField_CANARY { token } }');
        self::assertNotNull($r);
        self::assertSame(400, $r->status);
        self::assertStringContainsString('GRAPHQL_VALIDATION_FAILED', $r->body);
        // An embedded host has no reflect authorization: the submitted field name is never echoed back.
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
