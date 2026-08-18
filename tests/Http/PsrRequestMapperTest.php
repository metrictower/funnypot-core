<?php

declare(strict_types=1);

namespace Funnypot\Tests\Http;

use Funnypot\Http\PsrRequestMapper;
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
}
