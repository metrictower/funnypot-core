<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Reaction;

use Funnypot\Core\Reaction\ParamIntent;
use Funnypot\Core\Reaction\QueryIntentClassifier;
use PHPUnit\Framework\TestCase;

/**
 * The strict, closed query classifier: only the documented key/value-shape matrix produces an intent,
 * the fixed cross-kind priority is order-independent, and every malformed/oversized/ambiguous input
 * degrades to null. These are the safety bounds an attacker would probe first.
 */
final class QueryIntentClassifierTest extends TestCase
{
    /**
     * @dataProvider matchProvider
     */
    public function test_recognized_shapes_classify(string $query, string $kind, string $key, string $value): void
    {
        $intent = QueryIntentClassifier::classify($query);
        self::assertNotNull($intent, $query);
        self::assertSame($kind, $intent->kind, $query);
        self::assertSame($key, $intent->key, $query);
        self::assertSame($value, $intent->value, $query);
    }

    /** @return iterable<string,array{0:string,1:string,2:string,3:string}> */
    public static function matchProvider(): iterable
    {
        yield 'file slash' => ['file=/etc/passwd', ParamIntent::KIND_FILE_READ, 'file', '/etc/passwd'];
        yield 'file traversal' => ['path=../../secret', ParamIntent::KIND_FILE_READ, 'path', '../../secret'];
        yield 'file backslash' => ['file=..\\windows\\win.ini', ParamIntent::KIND_FILE_READ, 'file', '..\\windows\\win.ini'];
        yield 'file familiar bare' => ['path=wp-config.php', ParamIntent::KIND_FILE_READ, 'path', 'wp-config.php'];
        yield 'file familiar dotenv' => ['file=.env', ParamIntent::KIND_FILE_READ, 'file', '.env'];
        yield 'page path-like' => ['page=/admin/index', ParamIntent::KIND_FILE_READ, 'page', '/admin/index'];
        yield 'redirect url' => ['url=https://evil.example/x', ParamIntent::KIND_REDIRECT_NOTICE, 'url', 'https://evil.example/x'];
        yield 'redirect scheme-relative' => ['next=//evil.example/x', ParamIntent::KIND_REDIRECT_NOTICE, 'next', '//evil.example/x'];
        yield 'redirect relative' => ['redirect=/dashboard', ParamIntent::KIND_REDIRECT_NOTICE, 'redirect', '/dashboard'];
        yield 'debug 1' => ['debug=1', ParamIntent::KIND_DEBUG_VIEW, 'debug', '1'];
        yield 'debug true ci' => ['debug=TRUE', ParamIntent::KIND_DEBUG_VIEW, 'debug', 'TRUE'];
        yield 'debug on' => ['debug=on', ParamIntent::KIND_DEBUG_VIEW, 'debug', 'on'];
        yield 'command' => ['cmd=id', ParamIntent::KIND_COMMAND_RESULT, 'cmd', 'id'];
        yield 'search q' => ['q=hello world', ParamIntent::KIND_SEARCH_RESULT, 'q', 'hello world'];
        yield 'search note' => ['note=call+me', ParamIntent::KIND_SEARCH_RESULT, 'note', 'call me'];
    }

    /**
     * @dataProvider nullProvider
     */
    public function test_unrecognized_or_malformed_shapes_are_null(string $query): void
    {
        self::assertNull(QueryIntentClassifier::classify($query), $query);
    }

    /** @return iterable<string,array{0:string}> */
    public static function nullProvider(): iterable
    {
        yield 'empty' => [''];
        yield 'page ordinary' => ['page=2'];
        yield 'page empty' => ['page='];
        yield 'q key only' => ['q'];
        yield 'q empty' => ['q='];
        yield 'unknown key path' => ['unknown=../etc/passwd'];
        yield 'array syntax' => ['q[]=a'];
        yield 'bracket key' => ['q[0]=a'];
        yield 'duplicate ci' => ['q=a&Q=b'];
        yield 'duplicate same' => ['file=/a&file=/b'];
        yield 'debug 2' => ['debug=2'];
        yield 'debug trailing space' => ['debug=TRUE '];
        yield 'file bare ordinary' => ['file=readme'];
        yield 'redirect empty' => ['url='];
        yield 'command empty' => ['cmd='];
        yield 'malformed percent end' => ['q=abc%'];
        yield 'malformed percent short' => ['q=ab%2'];
        yield 'malformed percent nonhex' => ['q=ab%zz'];
        yield 'nul byte' => ['q=a%00b'];
        yield 'cr byte' => ['q=a%0db'];
        yield 'lf byte' => ['q=a%0ab'];
        yield 'del byte' => ['q=a%7fb'];
        yield 'c1 byte' => ['q=a%c2%85b'];
        yield 'invalid utf8' => ['q=%ff%fe'];
    }

    public function test_cross_kind_priority_is_order_independent(): void
    {
        // file-read (priority 1) wins over search-result whichever pair comes first.
        $a = QueryIntentClassifier::classify('file=../x&q=hello');
        $b = QueryIntentClassifier::classify('q=hello&file=../x');
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame(ParamIntent::KIND_FILE_READ, $a->kind);
        self::assertSame(ParamIntent::KIND_FILE_READ, $b->kind);

        // redirect-notice (2) wins over debug-view (3) and command (4) regardless of order.
        $c = QueryIntentClassifier::classify('debug=1&url=/x&cmd=id');
        self::assertNotNull($c);
        self::assertSame(ParamIntent::KIND_REDIRECT_NOTICE, $c->kind);
    }

    public function test_single_pass_decode_does_not_re_decode(): void
    {
        // %252e%252e%252f decodes ONCE to the literal %2e%2e%2f — no slash, not a traversal.
        $intent = QueryIntentClassifier::classify('file=%252e%252e%252fetc');
        self::assertNull($intent, 'double-encoded traversal must not classify as file-read');

        // A value carrying an encoded '%' survives as a literal '%'.
        $q = QueryIntentClassifier::classify('q=100%25');
        self::assertNotNull($q);
        self::assertSame('100%', $q->value);
    }

    public function test_plus_is_a_space_and_percent_decodes_once(): void
    {
        $intent = QueryIntentClassifier::classify('q=a%2Bb+c');
        self::assertNotNull($intent);
        self::assertSame('a+b c', $intent->value);
    }

    public function test_a_valid_multibyte_value_is_accepted(): void
    {
        // é = %c3%a9 (valid 2-byte UTF-8).
        $intent = QueryIntentClassifier::classify('q=caf%c3%a9');
        self::assertNotNull($intent);
        self::assertSame("caf\xc3\xa9", $intent->value);
    }

    public function test_raw_query_length_boundary(): void
    {
        $ok = 'q=' . str_repeat('a', 254);          // total 256 bytes
        self::assertNotNull(QueryIntentClassifier::classify($ok));

        // Valid in every other respect (<=32 pairs, each value <=256, a real q=hit), but > 2048 bytes
        // raw — so ONLY the raw-length gate rejects it. Without that gate it would classify as search.
        $pairs = ['q=hit'];
        for ($i = 0; $i < 9; $i++) {
            $pairs[] = 'x' . $i . '=' . str_repeat('a', 250);
        }
        $long = implode('&', $pairs);
        self::assertGreaterThan(2048, strlen($long));
        self::assertLessThanOrEqual(32, count($pairs));
        self::assertNull(QueryIntentClassifier::classify($long));
    }

    public function test_decoded_value_length_boundary(): void
    {
        self::assertNotNull(QueryIntentClassifier::classify('q=' . str_repeat('a', 256)));
        self::assertNull(QueryIntentClassifier::classify('q=' . str_repeat('a', 257)));
    }

    public function test_pair_count_boundary(): void
    {
        // 32 pairs, the recognized one present => classifies.
        $pairs = ['q=hit'];
        for ($i = 0; $i < 31; $i++) {
            $pairs[] = 'x' . $i . '=1';
        }
        self::assertCount(32, $pairs);
        self::assertNotNull(QueryIntentClassifier::classify(implode('&', $pairs)));

        // 33 pairs => the whole query is rejected.
        $pairs[] = 'x99=1';
        self::assertCount(33, $pairs);
        self::assertNull(QueryIntentClassifier::classify(implode('&', $pairs)));
    }

    public function test_key_length_boundary(): void
    {
        // A 33-char key never matches the /^[a-z][a-z0-9_-]{0,31}$/ shape (unknown => ignored).
        self::assertNull(QueryIntentClassifier::classify(str_repeat('a', 33) . '=x'));
    }

    public function test_semicolon_is_data_not_a_separator(): void
    {
        // 'q=a;b=c' is a single pair whose value is 'a;b=c'.
        $intent = QueryIntentClassifier::classify('q=a;b=c');
        self::assertNotNull($intent);
        self::assertSame(ParamIntent::KIND_SEARCH_RESULT, $intent->kind);
        self::assertSame('a;b=c', $intent->value);
    }

    public function test_result_retains_only_canonical_fields(): void
    {
        $intent = QueryIntentClassifier::classify('utm=track&q=hello&ref=/a');
        self::assertNotNull($intent);
        // redirect-notice (ref) outranks search (q); the unknown utm pair is dropped entirely.
        self::assertSame(ParamIntent::KIND_REDIRECT_NOTICE, $intent->kind);
        self::assertSame('ref', $intent->key);
        self::assertSame(['v' => 1, 'kind' => 'redirect-notice', 'key' => 'ref', 'value' => '/a'], $intent->toArray());
    }
}
