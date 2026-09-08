<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests {
    use Funnypot\Core\RequestContext;
    use PHPUnit\Framework\TestCase;

    final class InputCeilingBodyReadSpy
    {
        /** @var int */
        public static $calls = 0;
    }

    final class RequestContextInputCeilingTest extends TestCase
    {
        /** @var array<mixed,mixed> */
        private $server;

        protected function setUp(): void
        {
            $this->server = $_SERVER;
            InputCeilingBodyReadSpy::$calls = 0;
        }

        protected function tearDown(): void
        {
            $_SERVER = $this->server;
        }

        /**
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_overlong_global_target_declines_before_headers_and_body_read(): void
        {
            $this->installBodyReadSpy();
            foreach ([4097, 65536] as $targetBytes) {
                $_SERVER = [
                    'REQUEST_METHOD' => 'POST',
                    'REQUEST_URI' => str_repeat('x', $targetBytes),
                    'HTTP_X_THROW' => new class {
                        public function __toString(): string
                        {
                            throw new \RuntimeException('header must not be converted');
                        }
                    },
                ];

                $context = RequestContext::fromGlobals();

                self::assertFalse($context->targetAdmitted);
                self::assertSame('/', $context->path);
                self::assertSame('', $context->query);
                self::assertSame([], $context->headers);
                self::assertNull($context->rawBody);
            }
            self::assertSame(0, InputCeilingBodyReadSpy::$calls);
        }

        /**
         * @runInSeparateProcess
         * @preserveGlobalState disabled
         */
        public function test_exact_4096_global_target_maps_bounded_headers_host_and_body(): void
        {
            $this->installBodyReadSpy();
            $_SERVER = [
                'REQUEST_METHOD' => 'POST',
                'REQUEST_URI' => str_repeat('p', 4096),
                'HTTP_HOST' => str_repeat('H', 513),
                'HTTP_X_LONG' => str_repeat('v', 9000),
                'SERVER_PROTOCOL' => 'HTTP/2',
            ];

            $context = RequestContext::fromGlobals();

            self::assertTrue($context->targetAdmitted);
            self::assertSame(4096, strlen($context->path));
            self::assertSame(512, strlen($context->host));
            self::assertSame(8192, strlen($context->headers['X-Long']));
            self::assertSame('2', $context->httpVersion);
            self::assertSame(1, InputCeilingBodyReadSpy::$calls);
        }

        public function test_non_string_global_target_uses_safe_root_fallback(): void
        {
            $_SERVER = ['REQUEST_URI' => ['invalid']];

            $context = RequestContext::fromGlobals();

            self::assertTrue($context->targetAdmitted);
            self::assertSame('/', $context->path);
        }

        private function installBodyReadSpy(): void
        {
            eval(<<<'PHP'
namespace Funnypot\Core;
function file_get_contents(...$args) {
    \Funnypot\Core\Tests\InputCeilingBodyReadSpy::$calls++;
    return \file_get_contents(...$args);
}
PHP
            );
        }
    }
}
