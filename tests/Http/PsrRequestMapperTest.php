<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Http\PsrRequestMapper;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\TestCase;

final class PsrRequestMapperTest extends TestCase
{
    public function test_maps_method_path_query_and_host(): void
    {
        $request = new ServerRequest('GET', 'https://example.test/.git/config?v=1');

        $context = PsrRequestMapper::map($request);

        self::assertSame('GET', $context->method);
        self::assertSame('/.git/config', $context->path);
        self::assertSame('v=1', $context->query);
        self::assertSame('example.test', $context->host);
        self::assertSame('https', $context->scheme);
    }

    public function test_maps_headers_flattening_multi_values(): void
    {
        $request = (new ServerRequest('GET', 'https://example.test/'))
            ->withHeader('X-Test', 'a')
            ->withAddedHeader('X-Test', 'b');

        $context = PsrRequestMapper::map($request);

        self::assertSame('a, b', $context->headers['X-Test']);
    }

    public function test_reads_body_and_rewinds_the_stream_for_the_downstream_handler(): void
    {
        $stream = Stream::create('field=value');
        $request = (new ServerRequest('POST', 'https://example.test/'))->withBody($stream);

        $context = PsrRequestMapper::map($request);

        self::assertSame('field=value', $context->rawBody);
        // The stream must be back at the start so a downstream handler (or the
        // framework's own body parser) can still read it after the mapper peeked.
        self::assertSame(0, $stream->tell());
        self::assertSame('field=value', $stream->getContents());
    }

    public function test_caps_a_huge_body_at_64kb_and_still_rewinds(): void
    {
        $source = str_repeat('A', 256 * 1024); // 256 KB — well past the 64 KB cap
        $stream = Stream::create($source);
        $request = (new ServerRequest('POST', 'https://example.test/'))->withBody($stream);

        $context = PsrRequestMapper::map($request);

        // Only the first 64 KB is captured — a multi-GB POST can never OOM the host worker.
        self::assertSame(65536, strlen((string) $context->rawBody));
        self::assertSame(substr($source, 0, 65536), $context->rawBody);
        // Rewound for the downstream handler, which still sees the FULL body.
        self::assertSame(0, $stream->tell());
        self::assertSame($source, $stream->getContents());
    }

    public function test_body_exactly_at_the_cap_is_kept_whole(): void
    {
        $source = str_repeat('B', 65536);
        $stream = Stream::create($source);
        $request = (new ServerRequest('POST', 'https://example.test/'))->withBody($stream);

        $context = PsrRequestMapper::map($request);

        self::assertSame($source, $context->rawBody);
        self::assertSame(65536, strlen((string) $context->rawBody));
    }

    public function test_reads_a_short_read_stream_fully_up_to_the_cap(): void
    {
        // PSR-7 read($n) may return fewer than $n bytes; a single read(65536) is not enough. The
        // read loop must keep going until the cap or eof — here 1000-byte chunks up to 64 KB.
        $source = str_repeat('C', 200 * 1024);
        $stream = new StubStream($source, 1000);
        $request = (new ServerRequest('POST', 'https://example.test/'))->withBody($stream);

        $context = PsrRequestMapper::map($request);

        self::assertSame(65536, strlen((string) $context->rawBody));
        self::assertSame(substr($source, 0, 65536), $context->rawBody);
        self::assertSame(0, $stream->tell());
    }

    public function test_a_throwing_stream_yields_null_body_not_an_exception(): void
    {
        // A stream that lies about isSeekable() and throws on rewind() must degrade to "no body
        // captured" — never escape as a host 500 (same fail-safe family as the closure wrapping).
        $stream = new StubStream('field=value', PHP_INT_MAX, true);
        $request = (new ServerRequest('POST', 'https://example.test/'))->withBody($stream);

        $context = PsrRequestMapper::map($request);

        self::assertNull($context->rawBody);
    }
}
