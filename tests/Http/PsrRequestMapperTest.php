<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests\Http;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\Http\PsrRequestMapper;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use Nyholm\Psr7\Uri;
use PHPUnit\Framework\TestCase;

final class PsrRequestMapperTest extends TestCase
{
    public function test_rejects_exact_overlong_target_before_uri_headers_or_body(): void
    {
        foreach ([4097, 65536] as $targetBytes) {
            $request = new class('GET', '/', $targetBytes) extends ServerRequest {
                /** @var int */
                private $targetBytes;

                public function __construct(string $method, string $uri, int $targetBytes)
                {
                    parent::__construct($method, $uri);
                    $this->targetBytes = $targetBytes;
                }

                public function getRequestTarget(): string
                {
                    return str_repeat('x', $this->targetBytes);
                }

                public function getUri(): \Psr\Http\Message\UriInterface
                {
                    throw new \RuntimeException('URI must not be read');
                }

                public function getHeaders(): array
                {
                    throw new \RuntimeException('headers must not be read');
                }

                public function getBody(): \Psr\Http\Message\StreamInterface
                {
                    throw new \RuntimeException('body must not be read');
                }
            };

            $context = PsrRequestMapper::map($request);

            self::assertFalse($context->targetAdmitted);
            self::assertSame('/', $context->path);
            self::assertSame([], $context->headers);
            self::assertNull($context->rawBody);
        }
    }

    public function test_throwing_exact_target_fails_closed_before_other_accessors(): void
    {
        $request = new class('GET', '/') extends ServerRequest {
            public function getRequestTarget(): string
            {
                throw new \RuntimeException('target unavailable');
            }

            public function getUri(): \Psr\Http\Message\UriInterface
            {
                throw new \RuntimeException('URI must not be read');
            }
        };

        self::assertFalse(PsrRequestMapper::map($request)->targetAdmitted);
    }

    public function test_rejects_inverse_short_target_oversized_uri_before_headers_or_body(): void
    {
        $uri = new class('/') extends Uri {
            public function getPath(): string
            {
                return str_repeat('p', 4097);
            }
        };
        $request = new class('GET', $uri) extends ServerRequest {
            public function getRequestTarget(): string
            {
                return '/short';
            }

            public function getHeaders(): array
            {
                throw new \RuntimeException('headers must not be read');
            }

            public function getBody(): \Psr\Http\Message\StreamInterface
            {
                throw new \RuntimeException('body must not be read');
            }
        };

        self::assertFalse(PsrRequestMapper::map($request)->targetAdmitted);
    }

    public function test_exact_4096_custom_target_is_accepted(): void
    {
        $request = (new ServerRequest('GET', 'https://example.test/ok'))
            ->withRequestTarget(str_repeat('t', 4096));

        $context = PsrRequestMapper::map($request);

        self::assertTrue($context->targetAdmitted);
        self::assertSame('/ok', $context->path);
    }

    public function test_caps_uri_host_before_context_and_never_reads_unbounded_header_line(): void
    {
        foreach ([511, 512, 513, 1024 * 1024] as $hostBytes) {
            $uri = new class('/', $hostBytes) extends Uri {
                /** @var int */
                private $hostBytes;

                public function __construct(string $uri, int $hostBytes)
                {
                    parent::__construct($uri);
                    $this->hostBytes = $hostBytes;
                }

                public function getHost(): string
                {
                    return str_repeat('h', $this->hostBytes);
                }
            };
            $request = new class('GET', $uri) extends ServerRequest {
                public function getHeaderLine($name): string
                {
                    throw new \RuntimeException('getHeaderLine must not be used');
                }
            };

            $context = PsrRequestMapper::map($request);

            self::assertSame(min(512, $hostBytes), strlen($context->host));
        }
    }

    public function test_mapper_canonical_header_snapshot_stops_after_128_fields(): void
    {
        $request = new class('GET', '/') extends ServerRequest {
            public function getHeaders(): array
            {
                $headers = [];
                for ($i = 0; $i < 200; $i++) {
                    $headers['X-' . $i] = [str_repeat('v', 9000)];
                }

                return $headers;
            }

            public function getHeaderLine($name): string
            {
                throw new \RuntimeException('getHeaderLine must not be used');
            }
        };

        $context = PsrRequestMapper::map($request);

        self::assertLessThanOrEqual(128, count($context->headers));
        self::assertLessThanOrEqual(65536, array_sum(array_map('strlen', $context->headers)));
        self::assertArrayNotHasKey('X-128', $context->headers);
    }

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

    public function test_passes_the_protocol_version(): void
    {
        $request = (new ServerRequest('GET', 'https://example.test/'))->withProtocolVersion('2');

        $context = PsrRequestMapper::map($request);

        self::assertSame('2', $context->httpVersion);
    }

    public function test_host_fallback_is_case_insensitive(): void
    {
        // Relative URI (no URI host), only a lowercase `host` header — the h2 wire form.
        $lower = (new ServerRequest('GET', '/.git/config'))->withHeader('host', 'example.test');
        // Same origin, uppercase `Host` — the h1 wire form.
        $upper = (new ServerRequest('GET', '/.git/config'))->withHeader('Host', 'example.test');

        $lowerCtx = PsrRequestMapper::map($lower);
        $upperCtx = PsrRequestMapper::map($upper);

        self::assertSame('example.test', $lowerCtx->host);
        // Persona-seed parity: h1 and h2 must resolve the identical host (the strtolower fallback).
        self::assertSame($upperCtx->host, $lowerCtx->host);
    }

    public function test_numeric_header_name_does_not_break_the_host_fallback(): void
    {
        // PSR-7 implementations store an all-digit header name as an int array key; the relative-URI
        // Host fallback walks every key and must treat it as its string name, not throw.
        $request = new class('GET', '/probe') extends ServerRequest {
            public function getHeaders(): array
            {
                return [123 => ['x'], 'Host' => ['example.test']];
            }
        };

        $context = PsrRequestMapper::map($request);

        self::assertSame('example.test', $context->host);
        self::assertSame('x', $context->headers[123]);
    }

    public function test_mixed_case_host_header_is_lowercased_for_a_stable_seed(): void
    {
        // Uri::getHost() is normalized lowercase; a raw header line is not. Without strtolower an
        // EXAMPLE.COM host (h1) would seed a different persona than example.com (h2).
        $ctx = PsrRequestMapper::map((new ServerRequest('GET', '/probe'))->withHeader('Host', 'EXAMPLE.COM'));

        self::assertSame('example.com', $ctx->host);
    }

    public function test_persona_seed_input_is_identical_for_h1_and_h2_requests(): void
    {
        // Acceptance criterion: persona is deterministic across HTTP/1.1 and HTTP/2. Two requests
        // for the same origin — one h1 (`Host`, 1.1), one h2 (`host`, 2) — must feed the persona
        // selector the identical seed, and (stronger) yield byte-identical served bytes.
        $h1 = (new ServerRequest('GET', '/.git/config'))
            ->withHeader('Host', 'example.test')
            ->withProtocolVersion('1.1');
        $h2 = (new ServerRequest('GET', '/.git/config'))
            ->withHeader('host', 'example.test')
            ->withProtocolVersion('2');

        $h1Ctx = PsrRequestMapper::map($h1);
        $h2Ctx = PsrRequestMapper::map($h2);

        $config = new Config('respond', static function (RequestContext $r): bool { return true; });
        self::assertSame($config->seedFor($h1Ctx), $config->seedFor($h2Ctx));

        $store = new PhpArrayStore(require __DIR__ . '/../../resources/compiled/nuclei-index.php');
        $r1 = (new Honeypot($store, $config))->respond($h1Ctx);
        $r2 = (new Honeypot($store, $config))->respond($h2Ctx);

        self::assertNotNull($r1);
        self::assertNotNull($r2);
        self::assertSame($r1->body, $r2->body);
    }
}
