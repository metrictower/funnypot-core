<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Detection;
use Funnypot\Core\Http\ResponseEmitter;
use Funnypot\Core\SynthesizedResponse;
use PHPUnit\Framework\TestCase;

/**
 * FP-0252 Fix F: the pure headerLines() projection is unit-tested here (emit() itself stays
 * SAPI-bound and is exercised only for the sleep). Each entry is [line, replace].
 */
final class ResponseEmitterTest extends TestCase
{
    private function response(array $headers, string $body = 'body'): SynthesizedResponse
    {
        return new SynthesizedResponse(200, $headers, $body, Detection::none());
    }

    /** @return string[] just the 'Name: value' lines, order preserved */
    private function linesOnly(SynthesizedResponse $r): array
    {
        return array_map(static function (array $entry): string {
            return $entry[0];
        }, ResponseEmitter::headerLines($r));
    }

    public function test_header_lines_emit_each_set_cookie_value(): void
    {
        $lines = $this->linesOnly($this->response([
            'Set-Cookie' => ['fp_role=user; Path=/', 'PHPSESSID=abc; HttpOnly'],
        ]));

        self::assertContains('Set-Cookie: fp_role=user; Path=/', $lines);
        self::assertContains('Set-Cookie: PHPSESSID=abc; HttpOnly', $lines);
        // Order stable: first cookie precedes the second.
        self::assertLessThan(
            array_search('Set-Cookie: PHPSESSID=abc; HttpOnly', $lines, true),
            array_search('Set-Cookie: fp_role=user; Path=/', $lines, true)
        );
    }

    public function test_header_lines_use_append_for_subsequent_set_cookie(): void
    {
        $entries = ResponseEmitter::headerLines($this->response([
            'Set-Cookie' => ['a=1', 'b=2'],
        ]));

        // Set-Cookie is never a replace (both entries append), so a host-set cookie survives too.
        $setCookie = array_values(array_filter($entries, static function (array $e): bool {
            return strncmp($e[0], 'Set-Cookie:', 11) === 0;
        }));
        self::assertFalse($setCookie[0][1]);
        self::assertFalse($setCookie[1][1]);
    }

    public function test_header_lines_drop_only_the_poisoned_element_of_a_multi_value(): void
    {
        $lines = $this->linesOnly($this->response([
            'Set-Cookie' => ["good=1", "bad=2\r\nInjected: x"],
        ]));

        self::assertContains('Set-Cookie: good=1', $lines);
        self::assertNotContains("Set-Cookie: bad=2\r\nInjected: x", $lines);
        // The poisoned element is gone, the clean one survives.
        $cookies = array_filter($lines, static function (string $l): bool {
            return strncmp($l, 'Set-Cookie:', 11) === 0;
        });
        self::assertCount(1, $cookies);
    }

    public function test_header_lines_first_emitted_element_of_a_multi_value_gets_the_replace_flag(): void
    {
        // Addendum (c): when the FIRST element of a multi-value NON-Set-Cookie header is dropped as
        // poisoned, the next surviving element must inherit the replace flag (true), not append.
        $entries = ResponseEmitter::headerLines($this->response([
            'X-Multi' => ["poison\r\nInjected: x", 'kept-value'],
        ]));

        $multi = array_values(array_filter($entries, static function (array $e): bool {
            return strncmp($e[0], 'X-Multi:', 8) === 0;
        }));
        self::assertCount(1, $multi);
        self::assertSame('X-Multi: kept-value', $multi[0][0]);
        self::assertTrue($multi[0][1], 'the surviving first element must replace, not append');
    }

    public function test_header_lines_add_content_length_when_absent(): void
    {
        $lines = $this->linesOnly($this->response(['Content-Type' => 'text/plain'], 'hello'));

        self::assertContains('Content-Length: 5', $lines);
    }

    public function test_content_length_counts_bytes_not_characters(): void
    {
        // A multibyte body: strlen() is the wire byte count, not the character count.
        $body = "\xC3\xA9\xC3\xA9"; // two 'é' chars = 4 bytes
        $lines = $this->linesOnly($this->response(['Content-Type' => 'text/plain'], $body));

        self::assertContains('Content-Length: 4', $lines);
    }

    public function test_content_length_not_added_when_present(): void
    {
        $lines = $this->linesOnly($this->response(['Content-Length' => '99'], 'hello'));

        // The declared value is kept; no second, contradictory Content-Length is synthesized.
        self::assertContains('Content-Length: 99', $lines);
        $cl = array_filter($lines, static function (string $l): bool {
            return stripos($l, 'Content-Length:') === 0;
        });
        self::assertCount(1, $cl);
    }

    public function test_content_length_not_added_when_chunked(): void
    {
        $lines = $this->linesOnly($this->response(['Transfer-Encoding' => 'chunked'], 'hello'));

        $cl = array_filter($lines, static function (string $l): bool {
            return stripos($l, 'Content-Length:') === 0;
        });
        self::assertCount(0, $cl);
    }

    public function test_single_string_headers_are_byte_identical_plus_content_length(): void
    {
        // Regression pin: a plain single-string header emits exactly one line unchanged.
        $lines = $this->linesOnly($this->response(['Content-Type' => 'application/json'], '{}'));

        self::assertContains('Content-Type: application/json', $lines);
    }

    public function test_emit_applies_delay_metadata(): void
    {
        $response = $this->response(['Content-Type' => 'text/plain'], 'x');
        $response->delayMicros = 20000; // 20 ms

        ob_start();
        $start = microtime(true);
        ResponseEmitter::emit($response);
        $elapsed = microtime(true) - $start;
        $out = ob_get_clean();

        self::assertGreaterThanOrEqual(0.02, $elapsed, 'emit() must apply the delay metadata');
        self::assertSame('x', $out);
    }
}
