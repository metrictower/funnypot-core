<?php

declare(strict_types=1);

namespace Funnypot\Core\Support {
    final class BoundedInspectionOperationSpy
    {
        /** @var int[] */
        public static $decodeLengths = [];

        /** @var int[] */
        public static $lowerLengths = [];
    }

    function rawurldecode($value)
    {
        BoundedInspectionOperationSpy::$decodeLengths[] = strlen($value);

        return \rawurldecode($value);
    }

    function strtolower($value)
    {
        BoundedInspectionOperationSpy::$lowerLengths[] = strlen($value);

        return \strtolower($value);
    }
}

namespace Funnypot\Core\Tests {
    use Funnypot\Core\RequestContext;
    use Funnypot\Core\Support\BoundedInspection;
    use Funnypot\Core\Support\BoundedInspectionOperationSpy;
    use PHPUnit\Framework\TestCase;

    final class BoundedInspectionOperationTest extends TestCase
    {
        protected function setUp(): void
        {
            BoundedInspectionOperationSpy::$decodeLengths = [];
            BoundedInspectionOperationSpy::$lowerLengths = [];
            StringConversionCounter::$calls = 0;
        }

        public function test_decode_and_lowercase_only_receive_bounded_inputs(): void
        {
            $body = str_repeat('%2525', 2000);
            $subject = BoundedInspection::requestSubject(new RequestContext('POST', '/', '', [], $body));
            BoundedInspection::canonicalPsrHeaders([
                str_repeat('N', 129) => ['skip'],
                str_repeat('A', 128) => ['keep'],
            ]);

            self::assertCount(2, BoundedInspectionOperationSpy::$decodeLengths);
            self::assertLessThanOrEqual(32768, max(BoundedInspectionOperationSpy::$decodeLengths));
            self::assertLessThanOrEqual(32768, strlen($subject));
            self::assertSame([128], BoundedInspectionOperationSpy::$lowerLengths);
        }

        public function test_header_iteration_converts_only_the_hard_examined_windows(): void
        {
            $canonical = [];
            for ($i = 0; $i < 200; $i++) {
                $canonical['X-' . $i] = [new StringConversionCounter('v')];
            }
            BoundedInspection::canonicalPsrHeaders($canonical);
            self::assertSame(128, StringConversionCounter::$calls);

            StringConversionCounter::$calls = 0;
            $generic = [];
            for ($i = 0; $i < 100; $i++) {
                $generic['Y-' . $i] = new StringConversionCounter('v');
            }
            BoundedInspection::genericHeaders($generic);
            self::assertSame(64, StringConversionCounter::$calls);
        }

        public function test_plain_php_overlong_header_name_is_rejected_before_normalization(): void
        {
            BoundedInspection::canonicalServerHeaders([
                'HTTP_' . str_repeat('A', 1024 * 1024) => 'value',
            ]);

            self::assertSame([], BoundedInspectionOperationSpy::$lowerLengths);
        }

        public function test_psr_value_iteration_stops_at_256_and_16_per_field(): void
        {
            $headers = [];
            for ($field = 0; $field < 20; $field++) {
                $headers['X-' . $field] = [];
                for ($value = 0; $value < 20; $value++) {
                    $headers['X-' . $field][] = new StringConversionCounter('v');
                }
            }

            BoundedInspection::canonicalPsrHeaders($headers);

            self::assertSame(256, StringConversionCounter::$calls);
        }

        /**
         * @runInSeparateProcess
         */
        public function test_large_preallocated_context_adds_only_a_bounded_working_set(): void
        {
            $body = str_repeat('x', 8 * 1024 * 1024);
            $request = new RequestContext('POST', '/', '', ['X-Large' => $body], $body);
            $before = memory_get_peak_usage(false);

            $subject = BoundedInspection::requestSubject($request);
            $headers = BoundedInspection::genericHeaders($request->headers);
            $delta = memory_get_peak_usage(false) - $before;

            self::assertSame(32768, strlen($subject));
            self::assertSame(4096, strlen($headers['X-Large']));
            self::assertLessThan(2 * 1024 * 1024, $delta);
        }
    }

    final class StringConversionCounter
    {
        /** @var int */
        public static $calls = 0;

        /** @var string */
        private $value;

        public function __construct(string $value)
        {
            $this->value = $value;
        }

        public function __toString(): string
        {
            self::$calls++;

            return $this->value;
        }
    }
}
