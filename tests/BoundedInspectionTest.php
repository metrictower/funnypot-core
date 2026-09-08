<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Behavior\DecoySession;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;
use Funnypot\Core\Support\OobHaystack;
use PHPUnit\Framework\TestCase;

final class BoundedInspectionTest extends TestCase
{
    public function test_target_boundaries_count_raw_bytes_and_optional_query_separator(): void
    {
        self::assertSame(4096, BoundedInspection::targetBytes(str_repeat('a', 4096), ''));
        self::assertTrue(BoundedInspection::targetComponentsAccepted(str_repeat('a', 4096), ''));
        self::assertFalse(BoundedInspection::targetComponentsAccepted(str_repeat('a', 4097), ''));

        self::assertSame(4096, BoundedInspection::targetBytes('/', str_repeat('q', 4094)));
        self::assertTrue(BoundedInspection::targetComponentsAccepted('/', str_repeat('q', 4094)));
        self::assertFalse(BoundedInspection::targetComponentsAccepted('/', str_repeat('q', 4095)));
        self::assertTrue(BoundedInspection::rawTargetAccepted(str_repeat("\xff", 4096)));
        self::assertFalse(BoundedInspection::rawTargetAccepted(str_repeat("\xc3\xa9", 2049)));
    }

    public function test_context_admission_requires_flag_and_reconstructed_target_to_fit(): void
    {
        self::assertTrue(BoundedInspection::targetAccepted(new RequestContext('GET', '/ok')));
        self::assertFalse(BoundedInspection::targetAccepted(
            new RequestContext('GET', '/ok', '', [], null, '', 'https', '', false)
        ));
        self::assertFalse(BoundedInspection::targetAccepted(
            new RequestContext('GET', str_repeat('x', 4097))
        ));
    }

    public function test_request_subject_is_capped_before_each_decode_and_keeps_two_decode_layers(): void
    {
        $encoded = 'q=%252Fetc%252Fpasswd';
        $subject = BoundedInspection::requestSubject(new RequestContext('POST', '/x', $encoded, [], 'tail'));

        self::assertLessThanOrEqual(BoundedInspection::SUBJECT_BYTES, strlen($subject));
        self::assertStringContainsString($encoded, $subject);
        self::assertStringContainsString('q=%2Fetc%2Fpasswd', $subject);
        self::assertStringContainsString('q=/etc/passwd', $subject);

        $full = BoundedInspection::requestSubject(new RequestContext(
            'POST',
            '/',
            '',
            [],
            str_repeat('%25', 20000)
        ));
        self::assertSame(BoundedInspection::SUBJECT_BYTES, strlen($full));
    }

    public function test_canonical_psr_headers_enforce_value_field_and_aggregate_windows(): void
    {
        $manyValues = [];
        for ($i = 0; $i < 20; $i++) {
            $manyValues[] = 'v' . $i;
        }
        $source = [
            'X-Multi' => $manyValues,
            'x-multi' => ['tail'],
            str_repeat('N', 129) => ['skipped'],
            'X-Large' => [str_repeat('z', 9000)],
        ];
        for ($i = 0; $i < 200; $i++) {
            $source['X-' . $i] = ['a'];
        }

        $headers = BoundedInspection::canonicalPsrHeaders($source);

        self::assertSame(17, count(explode(', ', $headers['X-Multi'])));
        self::assertArrayNotHasKey('x-multi', $headers);
        self::assertArrayNotHasKey(str_repeat('N', 129), $headers);
        self::assertSame(8192, strlen($headers['X-Large']));
        self::assertLessThanOrEqual(BoundedInspection::CANONICAL_HEADER_BYTES, $this->serializedHeaderBytes($headers));
        self::assertArrayNotHasKey('X-125', $headers, 'the 128 examined-field stop must count skipped/duplicate fields');
    }

    public function test_canonical_psr_value_counter_stops_after_256_examined_values(): void
    {
        $source = [];
        for ($field = 0; $field < 20; $field++) {
            $source['X-' . $field] = array_fill(0, 16, 'v');
        }

        $headers = BoundedInspection::canonicalPsrHeaders($source);

        self::assertCount(16, $headers);
        self::assertArrayNotHasKey('X-16', $headers);
    }

    public function test_empty_multivalue_elements_keep_their_join_position(): void
    {
        self::assertSame(', b', BoundedInspection::canonicalPsrHeaders(['X-Test' => ['', 'b']])['X-Test']);
        self::assertSame(', b', BoundedInspection::genericHeaders(['X-Test' => '', 'x-test' => 'b'])['X-Test']);
    }

    public function test_generic_projection_stops_after_64_examined_fields_and_16kb(): void
    {
        $headers = [];
        for ($i = 0; $i < 80; $i++) {
            $headers['X-' . $i] = str_repeat(chr(65 + ($i % 20)), 500);
        }

        $projection = BoundedInspection::genericHeaders($headers);

        self::assertLessThanOrEqual(64, count($projection));
        self::assertLessThanOrEqual(BoundedInspection::GENERIC_HEADER_BYTES, $this->serializedHeaderBytes($projection));
        self::assertArrayNotHasKey('X-64', $projection);
        self::assertLessThanOrEqual(BoundedInspection::GENERIC_HEADER_BYTES, strlen(BoundedInspection::headerSurface($headers)));
    }

    public function test_generic_projection_does_not_replace_oob_canonical_window(): void
    {
        $headers = [];
        for ($i = 0; $i < 10; $i++) {
            $headers['X-Pad-' . $i] = str_repeat('p', 2000);
        }
        $headers['X-Late-Oob'] = 'late-window-marker.oastify.com';
        $canonical = BoundedInspection::canonicalPsrHeaders(array_map(static function (string $value): array {
            return [$value];
        }, $headers));
        $request = new RequestContext('GET', '/', '', $canonical);

        self::assertStringNotContainsString('late-window-marker', BoundedInspection::headerSurface($canonical));
        self::assertStringContainsString('late-window-marker', OobHaystack::raw($request));
    }

    public function test_host_and_cookie_windows_fail_closed(): void
    {
        self::assertSame(str_repeat('h', 512), BoundedInspection::host(str_repeat('h', 513)));
        self::assertNull(BoundedInspection::cookiePairs(str_repeat('x', 8193)));
        self::assertNull(BoundedInspection::cookiePairs(str_repeat('n', 257) . '=v'));
        self::assertNull(BoundedInspection::cookiePairs('n=' . str_repeat('v', 4097)));
        self::assertNull(BoundedInspection::cookiePairs(implode(';', array_fill(0, 65, 'n=v'))));
        self::assertSame([['a', '1'], ['b', 'two=parts']], BoundedInspection::cookiePairs('a=1; b=two=parts'));

        $session = new DecoySession('key');
        $cookie = $session->mintCookie('sess', '/');
        $value = substr($cookie, strlen('sess='), strpos($cookie, ';') - strlen('sess='));
        self::assertFalse($session->isAuthenticated('sess=' . $value . '; junk=' . str_repeat('x', 8192), 'sess'));
    }

    /** @param array<string,string> $headers */
    private function serializedHeaderBytes(array $headers): int
    {
        $bytes = 0;
        foreach ($headers as $name => $value) {
            $bytes += strlen($name) + 2 + strlen($value) + 2;
        }

        return $bytes;
    }
}
