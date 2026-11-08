<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Support;

use Funnypot\Core\Support\GraphQlSelection;
use PHPUnit\Framework\TestCase;

final class GraphQlSelectionTest extends TestCase
{
    public const INTROSPECTION_QUERY = <<<'GQL'
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }

    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }

    fragment InputValue on __InputValue {
      name
      description
      type { ...TypeRef }
      defaultValue
    }

    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    GQL;

    public function test_aliases_nesting_and_positions(): void
    {
        $doc = GraphQlSelection::parse("{\n  a: users { e: email id }\n}");

        self::assertNull($doc->failure);
        $root = $doc->operations[0]['selection'][0];
        self::assertSame('a', $root['alias']);
        self::assertSame('users', $root['name']);
        self::assertSame([2, 3], [$root['line'], $root['column']]);
        self::assertSame([2, 12], [$root['braceLine'], $root['braceColumn']]);
        self::assertSame(['email', 'id'], array_column($root['children'], 'name'));
        self::assertSame('e', $root['children'][0]['alias']);
    }

    public function test_arguments_comments_and_block_strings_are_skipped(): void
    {
        $doc = GraphQlSelection::parse(
            "# a comment\nquery Q(\$x: ID = \"{)\") { users(filter: {name: \"}(\" tags: [\"a\" \"b\"]}, note: \"\"\"multi\nline }\"\"\") { id } }"
        );

        self::assertNull($doc->failure);
        self::assertSame('Q', $doc->operations[0]['name']);
        self::assertSame(['id'], array_column($doc->operations[0]['selection'][0]['children'], 'name'));
    }

    public function test_a_leading_bom_is_ignored(): void
    {
        $doc = GraphQlSelection::parse("\xEF\xBB\xBF{ users { id } }");

        self::assertNull($doc->failure);
        self::assertSame(3, $doc->operations[0]['selection'][0]['column']);
    }

    public function test_multiple_operations_and_fragments(): void
    {
        $doc = GraphQlSelection::parse('query A { users { id } } mutation B { updateUserRole { success } } fragment F on User { id }');

        self::assertNull($doc->failure);
        self::assertSame(['A', 'B'], array_column($doc->operations, 'name'));
        self::assertSame(['query', 'mutation'], array_column($doc->operations, 'type'));
        self::assertArrayHasKey('F', $doc->fragments);
    }

    public function test_the_standard_introspection_query_parses(): void
    {
        $doc = GraphQlSelection::parse(self::INTROSPECTION_QUERY);

        self::assertNull($doc->failure);
        self::assertSame('__schema', $doc->operations[0]['selection'][0]['name']);
        self::assertSame(['FullType', 'InputValue', 'TypeRef'], array_keys($doc->fragments));
    }

    public function test_type_argument_is_read_only_in_its_simple_form(): void
    {
        $doc = GraphQlSelection::parse('{ __type(name: "User") { name } t: __typename }');
        self::assertSame('User', $doc->operations[0]['selection'][0]['typeArg']);
        self::assertSame('__typename', $doc->operations[0]['selection'][1]['name']);

        $other = GraphQlSelection::parse('{ __type(name: $n) { name } }');
        self::assertNull($other->operations[0]['selection'][0]['typeArg']);
    }

    public function test_spreads_and_directives_are_recorded(): void
    {
        $doc = GraphQlSelection::parse('{ users @skip(if: true) { ...F ... on User { id } } }');

        self::assertNull($doc->failure);
        $users = $doc->operations[0]['selection'][0];
        self::assertTrue($users['directives']);
        self::assertSame(['spread', 'inline'], array_column($users['children'], 'kind'));
    }

    /** @return array<string,array{0:string,1:string,2:int,3:int}> */
    public function syntaxProvider(): array
    {
        return [
            'empty document' => ['', 'Syntax Error: Unexpected <EOF>.', 1, 1],
            'unclosed selection' => ['{ users', 'Syntax Error: Expected Name, found <EOF>.', 1, 8],
            'empty selection' => ['{ }', 'Syntax Error: Expected Name, found "}".', 1, 3],
            'stray punctuator' => ['{ : }', 'Syntax Error: Expected Name, found ":".', 1, 3],
            'unterminated string' => ['{ a(b: "x', 'Syntax Error: Unterminated string.', 1, 10],
            'unterminated block string' => ["{ a(b: \"\"\"x\ny", 'Syntax Error: Unterminated string.', 2, 2],
            'eof inside arguments' => ['{ a(b: 1', 'Syntax Error: Unexpected <EOF>.', 1, 9],
        ];
    }

    /** @dataProvider syntaxProvider */
    public function test_syntax_errors_use_a_closed_vocabulary(string $src, string $message, int $line, int $column): void
    {
        $doc = GraphQlSelection::parse($src);

        self::assertSame('syntax', $doc->failure);
        self::assertSame($message, $doc->message);
        self::assertSame([$line, $column], [$doc->line, $doc->column]);
    }

    /** @return array<string,array{0:string}> */
    public function declineProvider(): array
    {
        return [
            'unknown keyword' => ['queryy { a }'],
            'unexpected character' => ['{ a<b }'],
            'number where a name is expected' => ['{ a: 5 }'],
            'bad escape' => ['{ a(b: "\\q") }'],
            'over the byte cap' => ['{ ' . str_repeat('a ', GraphQlSelection::MAX_BYTES) . '}'],
        ];
    }

    /** @dataProvider declineProvider */
    public function test_anything_outside_the_vocabulary_declines(string $src): void
    {
        self::assertSame('decline', GraphQlSelection::parse($src)->failure);
    }

    public function test_deep_argument_nesting_does_not_recurse(): void
    {
        $src = '{ a(b: ' . str_repeat('(', 4000) . str_repeat(')', 4000) . ') }';
        $doc = GraphQlSelection::parse($src);

        self::assertNull($doc->failure);
        self::assertSame('a', $doc->operations[0]['selection'][0]['name']);
    }

    public function test_deep_selection_nesting_does_not_recurse(): void
    {
        $src = str_repeat('{ a ', 1500) . str_repeat('}', 1500);
        $doc = GraphQlSelection::parse(substr($src, 0, -1) . '}');

        self::assertNull($doc->failure);
    }

    public function test_columns_count_utf16_units(): void
    {
        self::assertSame(2, GraphQlSelection::utf16Units("a\xC3\xA9"));       // a + é
        self::assertSame(3, GraphQlSelection::utf16Units("a\xF0\x9F\x98\x80")); // a + an astral char
        $doc = GraphQlSelection::parse("{ a(b: \"\xF0\x9F\x98\x80\") c }");
        self::assertSame(14, $doc->operations[0]['selection'][1]['column']);
    }
}
