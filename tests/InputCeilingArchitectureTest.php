<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

final class InputCeilingArchitectureTest extends TestCase
{
    public function test_operation_spies_are_not_installed_during_test_discovery(): void
    {
        require_once __DIR__ . '/BoundedInspectionOperationTest.php';
        require_once __DIR__ . '/DecoySessionProbeTest.php';
        require_once __DIR__ . '/InputCeilingTest.php';
        require_once __DIR__ . '/RequestContextInputCeilingTest.php';

        self::assertFalse(function_exists('Funnypot\\Core\\Support\\rawurldecode'));
        self::assertFalse(function_exists('Funnypot\\Core\\Support\\strtolower'));
        self::assertFalse(function_exists('Funnypot\\Core\\Template\\preg_match'));
        self::assertFalse(function_exists('Funnypot\\Core\\file_get_contents'));
        self::assertFalse(function_exists('Funnypot\\Core\\rawurldecode'));
        self::assertFalse(function_exists('Funnypot\\Core\\hash_equals'));
        self::assertFalse(function_exists('Funnypot\\Core\\trim'));
        self::assertFalse(function_exists('Funnypot\\Core\\strtolower'));
        self::assertFalse(function_exists('Funnypot\\Core\\filter_var'));
    }

    public function test_attack_emulator_has_no_independent_raw_request_builder_or_decoder(): void
    {
        $source = file_get_contents(__DIR__ . '/../src/Template/TemplateAttackEmulator.php');
        self::assertNotFalse($source);

        self::assertStringNotContainsString('rawurldecode(', $source);
        self::assertStringNotContainsString('$r->path . \' \' . $r->query', $source);
        self::assertStringNotContainsString("implode(' ', array_map('strval', \$r->headers))", $source);
        self::assertStringContainsString('BoundedInspection::surface(', $source);
    }

    public function test_adapters_do_not_recopy_host_or_flatten_psr_values_unbounded(): void
    {
        $globals = file_get_contents(__DIR__ . '/../src/RequestContext.php');
        $psr = file_get_contents(__DIR__ . '/../src/Http/PsrRequestMapper.php');
        self::assertNotFalse($globals);
        self::assertNotFalse($psr);

        self::assertStringNotContainsString("(string) (\$_SERVER['HTTP_HOST']", $globals);
        self::assertStringNotContainsString('getHeaderLine(', $psr);
        self::assertStringNotContainsString("implode(', ', \$values)", $psr);
        self::assertStringContainsString('canonicalServerHeaders(', $globals);
        self::assertStringContainsString('canonicalPsrHeaders(', $psr);
    }

    public function test_oob_keeps_its_distinct_three_decode_header_first_layout(): void
    {
        $source = file_get_contents(__DIR__ . '/../src/Support/OobHaystack.php');
        self::assertNotFalse($source);

        self::assertStringContainsString('public const MAX_DECODE_PASSES = 3;', $source);
        self::assertStringContainsString('public const TOTAL_CAP = 65536;', $source);
        self::assertStringContainsString('public const BODY_CAP = 16384;', $source);
        self::assertStringNotContainsString('BoundedInspection', $source);
    }
}
