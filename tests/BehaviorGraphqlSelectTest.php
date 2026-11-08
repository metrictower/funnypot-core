<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\SynthesizedResponse;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Tests\Support\GraphQlSelectionTest;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * The `graphql-select` GraphQL decoy answers the document in the request: the requested fields only,
 * graphql-js / Apollo errors, mutations refused as unauthenticated. Attacker-chosen names appear in error
 * messages only where the `graphql-name` reflect class is allowed (the box), and the answer never depends
 * on whether such a name looks like a detector signature.
 */
final class BehaviorGraphqlSelectTest extends TestCase
{
    private const TEMPLATE = __DIR__ . '/../templates/attack/39-graphql-introspection.yaml';

    private static function engine(bool $box = false, int $maxBodyBytes = 65536): Honeypot
    {
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool {
                return true;
            },
            'matched-only',
            null,
            'coherent',
            Style::REALISTIC,
            'high',
            $maxBodyBytes,
            0,
            0,
            true
        );
        if ($box) {
            $config->isolatedOrigin = true;
            $config->reflectorAuthorizer = static function (RequestContext $r, string $class): bool {
                return $class === 'graphql-name';
            };
        }

        return Honeypot::default($config);
    }

    private static function get(Honeypot $engine, string $query, string $path = '/graphql'): ?SynthesizedResponse
    {
        return $engine->respond(new RequestContext('GET', $path, 'query=' . rawurlencode($query), ['host' => 'gq.example'], null, 'gq.example', 'http'));
    }

    /** @param array<string,mixed> $payload */
    private static function post(Honeypot $engine, array $payload): ?SynthesizedResponse
    {
        return self::postRaw($engine, (string) json_encode($payload), 'application/json');
    }

    private static function postRaw(Honeypot $engine, string $body, string $type): ?SynthesizedResponse
    {
        return $engine->respond(new RequestContext('POST', '/graphql', '', ['host' => 'gq.example', 'Content-Type' => $type], $body, 'gq.example', 'http'));
    }

    /** @return array<string,mixed> */
    private static function json(?SynthesizedResponse $r): array
    {
        self::assertNotNull($r);
        $decoded = json_decode($r->body, true);
        self::assertIsArray($decoded, $r->body);

        return $decoded;
    }

    private static function base(): string
    {
        $doc = \Symfony\Component\Yaml\Yaml::parseFile(self::TEMPLATE);

        return (string) $doc['response']['body'];
    }

    // --- 1, 2: projection --------------------------------------------------------------------------

    public function test_only_the_requested_fields_are_returned(): void
    {
        $engine = self::engine();
        $users = self::get($engine, '{users{id email}}');
        $config = self::get($engine, '{systemConfig{awsAccessKeyId}}');

        self::assertSame(200, $users->status);
        $rows = self::json($users)['data']['users'];
        self::assertCount(5, $rows);
        foreach ($rows as $i => $row) {
            self::assertSame(['id', 'email'], array_keys($row));
            self::assertSame((string) ($i + 1), $row['id'], 'IDs are strings');
        }
        self::assertSame(['awsAccessKeyId'], array_keys(self::json($config)['data']['systemConfig']));
        self::assertNotSame($users->body, $config->body);
        self::assertSame(['viewer' => null], self::json(self::get($engine, '{viewer{email}}'))['data']);
    }

    public function test_aliases_key_the_response_and_duplicates_are_emitted_once(): void
    {
        $engine = self::engine();
        $a = self::json(self::get($engine, '{a: users{e: email}}'))['data'];
        self::assertSame(['a'], array_keys($a));
        self::assertSame(['e'], array_keys($a['a'][0]));

        $dup = self::json(self::get($engine, '{users{id id}}'))['data'];
        self::assertSame(['id'], array_keys($dup['users'][0]));
    }

    // --- 3, 4: errors and the name echo ------------------------------------------------------------

    public function test_unknown_fields_name_the_field_only_on_the_box(): void
    {
        $box = self::json(self::get(self::engine(true), '{foo}'));
        self::assertSame('Cannot query field "foo" on type "Query".', $box['errors'][0]['message']);
        self::assertSame([['line' => 1, 'column' => 2]], $box['errors'][0]['locations']);
        self::assertSame('GRAPHQL_VALIDATION_FAILED', $box['errors'][0]['extensions']['code']);

        self::assertSame(
            'Cannot query field "viewr" on type "Query". Did you mean "viewer"?',
            self::json(self::get(self::engine(true), '{viewr{id}}'))['errors'][0]['message']
        );

        $embedded = self::json(self::get(self::engine(), '{foo}'));
        self::assertSame('Cannot query field on type "Query".', $embedded['errors'][0]['message']);
        self::assertSame(
            'Cannot query field on type "Query". Did you mean "viewer"?',
            self::json(self::get(self::engine(), '{viewr{id}}'))['errors'][0]['message']
        );

        self::assertSame(
            'Field "viewer" of type "User" must have a selection of subfields. Did you mean "viewer { ... }"?',
            self::json(self::get(self::engine(), '{viewer}'))['errors'][0]['message']
        );
        self::assertSame(
            'Field "email" must not have a selection since type "String" has no subfields.',
            self::json(self::get(self::engine(), '{users{email{x}}}'))['errors'][0]['message']
        );
    }

    public function test_a_signature_shaped_name_never_changes_the_outcome(): void
    {
        foreach ([true, false] as $box) {
            $engine = self::engine($box);
            $shapes = [];
            foreach (['foo', 'honeypot', 'nuclei', 'xinteractshx'] as $name) {
                $r = self::get($engine, '{' . $name . '}');
                self::assertNotNull($r, $name);
                $message = self::json($r)['errors'][0]['message'];
                if ($box) {
                    self::assertSame('Cannot query field "' . $name . '" on type "Query".', $message);
                }
                $shapes[] = [$r->status, $r->headers['Content-Type'] ?? null, str_replace($name, '<name>', $message)];
            }
            self::assertCount(1, array_unique(array_map('serialize', $shapes)), $box ? 'box' : 'embedded');
        }

        $embedded = self::engine();
        foreach (['honeypot', 'foo'] as $alias) {
            $data = self::json(self::get($embedded, '{' . $alias . ': users{id}}'))['data'];
            self::assertSame([$alias], array_keys($data), 'an alias is a response key on every deploy');
        }
    }

    public function test_the_compiled_rule_is_never_suppressed_on_an_embedded_host(): void
    {
        foreach (require __DIR__ . '/../resources/compiled/funnypot-attack.php' as $rule) {
            if (($rule['id'] ?? '') === 'attack-graphql-introspection') {
                self::assertArrayNotHasKey('reflects_input', $rule);
                self::assertSame('graphql-select', $rule['behavior']);

                return;
            }
        }
        self::fail('rule not compiled');
    }

    // --- 5: mutations ------------------------------------------------------------------------------

    public function test_mutations_are_refused_as_unauthenticated(): void
    {
        $engine = self::engine();
        $r = self::post($engine, ['query' => 'mutation{updateUserRole(userId:"999999",role:"billing"){success}}']);
        self::assertSame(200, $r->status);
        $body = self::json($r);
        self::assertSame('You must be logged in to perform this action.', $body['errors'][0]['message']);
        self::assertSame(['updateUserRole'], $body['errors'][0]['path']);
        self::assertSame('UNAUTHENTICATED', $body['errors'][0]['extensions']['code']);
        self::assertSame(['updateUserRole' => null], $body['data']);
        self::assertSame(['message', 'locations', 'path', 'extensions'], array_keys($body['errors'][0]));

        $typename = self::json(self::post($engine, ['query' => 'mutation{__typename}']));
        self::assertSame(['data' => ['__typename' => 'Mutation']], $typename, 'no errors key when nothing failed');

        $bare = self::json(self::post($engine, ['query' => 'mutation{updateUserRole(userId:"999999",role:"x")}']));
        self::assertStringContainsString('of type "MutationResult" must have a selection of subfields', $bare['errors'][0]['message']);

        $get = self::get($engine, 'mutation{updateUserRole(userId:"1",role:"x"){success}}');
        self::assertSame(405, $get->status);
        self::assertSame('POST', $get->headers['Allow'] ?? null);
        self::assertSame('BAD_REQUEST', self::json($get)['errors'][0]['extensions']['code']);
    }

    // --- 6: introspection --------------------------------------------------------------------------

    public function test_the_standard_introspection_query_gets_a_complete_schema(): void
    {
        $schema = self::json(self::post(self::engine(), ['query' => GraphQlSelectionTest::INTROSPECTION_QUERY]))['data']['__schema'];

        $declared = array_column($schema['types'], 'name');
        $refs = [];
        array_walk_recursive($schema, static function ($value, $key) use (&$refs): void {
            if ($key === 'name' && is_string($value)) {
                $refs[] = $value;
            }
        });
        foreach (['Query', 'Mutation', 'User', 'SystemConfig', 'MutationResult', 'ID', 'String', 'Boolean'] as $type) {
            self::assertContains($type, $declared);
        }
        $stack = [$schema];
        while ($stack !== []) {
            $node = array_pop($stack);
            foreach ($node as $key => $value) {
                if (!is_array($value)) {
                    continue;
                }
                if (($key === 'type' || $key === 'ofType') && isset($value['kind']) && is_string($value['name'] ?? null)) {
                    self::assertContains($value['name'], $declared, 'no dangling type reference');
                }
                $stack[] = $value;
            }
        }
    }

    public function test_typename_and_type_lookups(): void
    {
        $engine = self::engine();
        self::assertSame(['__typename' => 'Query'], self::json(self::get($engine, '{__typename}'))['data']);
        self::assertSame(['viewer' => null], self::json(self::get($engine, '{viewer{__typename id}}'))['data'],
            '__typename inside a data query is projected, not the schema');
        self::assertSame('User', self::json(self::get($engine, '{__type(name:"User"){name}}'))['data']['__type']['name']);
        self::assertNull(self::json(self::get($engine, '{__type(name:"Nope"){name}}'))['data']['__type']);

        self::assertSame(
            'Field "__schema" of type "__Schema!" must have a selection of subfields. Did you mean "__schema { ... }"?',
            self::json(self::get($engine, '{__schema}'))['errors'][0]['message']
        );
        self::assertSame(400, self::get($engine, '{__type(name:"User")}')->status);
    }

    public function test_root_fragments_are_expanded(): void
    {
        $engine = self::engine();
        $named = self::json(self::post($engine, ['query' => 'query { ...Root } fragment Root on Query { __typename users { id } }']));
        self::assertSame(['__typename', 'users'], array_keys($named['data']));
        self::assertSame(['__typename' => 'Query'], self::json(self::get($engine, '{ ... on Query { __typename } }'))['data']);
        self::assertSame(self::base(), self::get($engine, '{ ...Missing }')->body, 'an unknown fragment declines');
    }

    public function test_aliased_introspection_stays_within_the_body_cap(): void
    {
        $aliased = static function (int $n): string {
            $fields = '';
            for ($i = 0; $i < $n; $i++) {
                $fields .= " a{$i}: __schema { types { name } }";
            }

            return '{' . $fields . ' }';
        };
        $engine = self::engine();
        self::assertSame(200, self::postRaw($engine, $aliased(2), 'application/graphql')->status);
        foreach ([13, 40] as $n) {
            $r = self::postRaw($engine, $aliased($n), 'application/graphql');
            self::assertSame(self::base(), $r->body, "{$n} aliased schemas decline to the rule's own base");
        }

        $small = self::engine(false, 8192);
        self::assertSame(200, self::postRaw($small, $aliased(1), 'application/graphql')->status);
        self::assertSame(self::base(), self::postRaw($small, $aliased(2), 'application/graphql')->body);
    }

    public function test_alias_names_are_bounded(): void
    {
        $engine = self::engine();
        $ok = str_repeat('a', 64);
        $long = str_repeat('a', 65);
        self::assertSame([$ok], array_keys(self::json(self::get($engine, '{' . $ok . ': __typename}'))['data']));
        self::assertSame(self::base(), self::get($engine, '{' . $long . ': __typename}')->body);
        self::assertSame(self::base(), self::get($engine, '{users{' . $long . ': id}}')->body);
    }

    public function test_answers_end_with_a_newline_like_the_base(): void
    {
        $engine = self::engine();
        self::assertStringEndsWith("}\n", self::base());
        foreach (['{users{id}}', '{foo}', 'mutation{updateUserRole{success}}', '{'] as $q) {
            self::assertStringEndsWith("}\n", self::get($engine, $q)->body, $q);
        }
    }

    public function test_the_self_scan_declines_every_query_for_a_flagged_config(): void
    {
        $emulator = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $rule = $emulator->ruleById('attack-graphql-introspection');
        self::assertNotNull($rule);
        $request = static function (string $query): RequestContext {
            return new RequestContext('GET', '/graphql', 'query=' . rawurlencode($query), ['host' => 'gq.example'], null, 'gq.example', 'http');
        };
        $serve = static function (TemplateAttackEmulator $e, string $query) use ($rule, $request): string {
            $r = $e->renderRule($rule, [], 7, $request($query));
            self::assertNotNull($r);

            return $r->body;
        };
        self::assertNotSame(self::base(), $serve($emulator, '{users{id}}'), 'the real guard passes the dataset');

        $setGuard = static function (TemplateAttackEmulator $e, ?FingerprintGuard $guard): void {
            $loaded = new \ReflectionProperty(TemplateAttackEmulator::class, 'fingerprintGuardLoaded');
            $loaded->setAccessible(true);
            $loaded->setValue($e, true);
            $slot = new \ReflectionProperty(TemplateAttackEmulator::class, 'fingerprintGuard');
            $slot->setAccessible(true);
            $slot->setValue($e, $guard);
        };
        // A token only the dataset carries, and one only the schema carries: either declines everything,
        // including queries that never select it.
        foreach (['stripeSecretKey', 'MutationResult', 'UNAUTHENTICATED'] as $token) {
            $flagged = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
            $setGuard($flagged, new FingerprintGuard([$token], []));
            foreach (['{users{id}}', '{__typename}', '{foo}', '{'] as $q) {
                self::assertSame(self::base(), $serve($flagged, $q), "{$token} / {$q}");
            }
        }

        $unverifiable = TemplateAttackEmulator::fromFile(__DIR__ . '/../resources/compiled/funnypot-attack.php');
        $setGuard($unverifiable, null);
        self::assertSame(self::base(), $serve($unverifiable, '{users{id}}'), 'no guard fails closed');
    }

    // --- 7: input forms and bounds ----------------------------------------------------------------

    public function test_input_forms(): void
    {
        $engine = self::engine();
        self::assertSame(200, self::postRaw($engine, '{users{id}}', 'application/graphql')->status);
        self::assertSame(200, $engine->respond(new RequestContext('GET', '/graphql', 'query=%7Busers+%7Bid%7D%7D', ['host' => 'gq.example'], null, 'gq.example', 'http'))->status);

        $two = 'query A { users { id } } query B { systemConfig { awsAccessKeyId } }';
        self::assertSame(['systemConfig'], array_keys(self::json(self::post($engine, ['query' => $two, 'operationName' => 'B', 'variables' => ['x' => 1]]))['data']));
        self::assertSame('Must provide operation name if query contains multiple operations.', self::json(self::post($engine, ['query' => $two]))['errors'][0]['message']);

        foreach (['[{"query":"{users{id}}"}]', '{"query":"subscription { users { id } }"}', '{"query":5}'] as $body) {
            self::assertSame(self::base(), self::postRaw($engine, $body, 'application/json')->body, $body);
        }
    }

    public function test_bounds_have_defined_outcomes(): void
    {
        $engine = self::engine();
        $wide = static function (int $aliases): string {
            $fields = '';
            for ($i = 0; $i < $aliases; $i++) {
                $fields .= " a{$i}: id";
            }

            return '{users{' . $fields . ' }}';
        };
        self::assertSame(200, self::get($engine, $wide(63))->status, '64 fields');
        self::assertSame(self::base(), self::get($engine, $wide(64))->body, '65 fields declines');

        $nest = static function (int $levels): string {
            return str_repeat('{a', $levels) . str_repeat('}', $levels);
        };
        self::assertStringContainsString('Cannot query field', self::get($engine, $nest(7))->body, 'depth 6 is allowed');
        self::assertSame("'' exceeds maximum operation depth of 6", self::json(self::get($engine, $nest(8)))['errors'][0]['message']);

        $padded = static function (int $bytes): string {
            return '{users{id}}' . str_repeat(' ', $bytes - 11);
        };
        self::assertSame(200, self::postRaw($engine, $padded(8192), 'application/graphql')->status);
        self::assertSame(self::base(), self::postRaw($engine, $padded(8193), 'application/graphql')->body);

        $deepArgs = '{users(f: ' . str_repeat('(', 1000) . str_repeat(')', 1000) . '){id}}';
        self::assertSame(200, self::postRaw($engine, $deepArgs, 'application/graphql')->status);
        self::assertSame(self::base(), self::postRaw($engine, '{users(}{{{ ]] ) {id}}', 'application/graphql')->body, 'mismatched brackets decline');

        $manyPairs = str_repeat('a&', 1010) . 'query=' . rawurlencode('{users{id}}');
        $r = $engine->respond(new RequestContext('GET', '/graphql', $manyPairs, ['host' => 'gq.example'], null, 'gq.example', 'http'));
        self::assertSame(self::base(), $r->body, 'too many query pairs decline without an input-limit warning');
        self::assertSame('Syntax Error: Unterminated string.', self::json(self::postRaw($engine, '{users(f: "x', 'application/graphql'))['errors'][0]['message']);
        self::assertSame('Syntax Error: Unterminated string.', self::json(self::postRaw($engine, '{users(f: """x', 'application/graphql'))['errors'][0]['message']);
    }

    // --- 8: port parity and determinism ----------------------------------------------------------

    public function test_the_position_blind_port_serves_the_base_response(): void
    {
        $engine = self::engine();
        $request = new RequestContext('GET', '/graphql', 'query=' . rawurlencode('{users{id}}'), ['host' => 'gq.example'], null, 'gq.example', 'http');
        $verdict = $engine->classify($request, SiteProfile::empty());
        $served = $engine->synthesize($verdict, SiteProfile::empty(), 'seed');

        self::assertNotNull($served);
        self::assertSame(self::base(), $served->body);
    }

    public function test_answers_are_deterministic(): void
    {
        $engine = self::engine();
        foreach (['{users{id email apiKey}}', '{foo}', GraphQlSelectionTest::INTROSPECTION_QUERY] as $q) {
            self::assertSame(self::get($engine, $q)->body, self::get($engine, $q)->body);
        }
    }

    // --- compiler --------------------------------------------------------------------------------

    /** @return array<string,array{0:string,1:string,2:string}> */
    public function badConfigProvider(): array
    {
        return [
            'unknown key' => ["graphql-select:\n", "graphql-select:\n  extra: 1\n", 'unknown key'],
            'dangling type' => ['"name":"MutationResult","ofType":null', '"name":"Missing","ofType":null', 'undeclared type'],
            'field missing from the introspection body' => ["      newRole: String\n", "      newRole: String\n      secret: String\n", 'not in the introspection body'],
            'list under a scalar field' => ["        isActive: false\n", "        isActive: [false]\n", 'must match its declared type'],
            'unknown dataset field' => ["        isActive: false\n", "        isActive: false\n        password: x\n", 'is not a field of User'],
        ];
    }

    /** @dataProvider badConfigProvider */
    public function test_the_compiler_rejects_an_inconsistent_config(string $from, string $to, string $error): void
    {
        $yaml = (string) file_get_contents(self::TEMPLATE);
        self::assertStringContainsString($from, $yaml);
        $dir = sys_get_temp_dir() . '/fp-gql-' . bin2hex(random_bytes(4));
        mkdir($dir);
        file_put_contents($dir . '/39-graphql.yaml', str_replace($from, $to, $yaml));
        try {
            $this->expectException(RuntimeException::class);
            $this->expectExceptionMessage($error);
            (new EmulatorCompiler())->compile($dir);
        } finally {
            unlink($dir . '/39-graphql.yaml');
            rmdir($dir);
        }
    }
}
