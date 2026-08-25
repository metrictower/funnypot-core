<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\EmulatorCompiler;
use Funnypot\Core\Compiler\RouteEmulatorCompiler;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use RuntimeException;

/**
 * Fail-safe forward-compat gate: a template declaring a schema `version:` ahead of what this
 * engine understands (SchemaVersion::CURRENT) must fail the compile rather than be silently
 * mis-parsed. No `version:` at all defaults to 1, so every existing (schema-less) template
 * keeps compiling unchanged.
 */
final class SchemaVersionCompilerTest extends TestCase
{
    private function normalizeAttack(array $doc): array
    {
        $compiler = new EmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'attack-schema-test.yaml');
    }

    private function baseAttackDoc(): array
    {
        return [
            'id' => 'attack-schema-test',
            'severity' => 'high',
            'tags' => ['attack', 'test'],
            'status' => 200,
            'match' => [['in' => 'path', 'regex' => 'never-matches-anything']],
            'response' => ['body' => 'x'],
        ];
    }

    public function test_attack_template_with_no_version_compiles_fine(): void
    {
        $rule = $this->normalizeAttack($this->baseAttackDoc());

        self::assertSame('attack-schema-test', $rule['id']);
    }

    public function test_attack_template_declaring_current_version_compiles_fine(): void
    {
        $doc = $this->baseAttackDoc();
        $doc['version'] = 1;

        $rule = $this->normalizeAttack($doc);

        self::assertSame('attack-schema-test', $rule['id']);
    }

    public function test_attack_template_declaring_a_future_version_is_refused(): void
    {
        $doc = $this->baseAttackDoc();
        $doc['version'] = 2;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/schema/i');

        $this->normalizeAttack($doc);
    }

    private function normalizeRoute(array $doc): array
    {
        $compiler = new RouteEmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'route-schema-test.yaml');
    }

    private function baseRouteDoc(): array
    {
        return [
            'id' => 'route-schema-test',
            'match' => ['pid' => ['route-schema-test']],
            'response' => ['body' => 'x'],
        ];
    }

    public function test_route_template_with_no_version_compiles_fine(): void
    {
        $rule = $this->normalizeRoute($this->baseRouteDoc());

        self::assertSame('route-schema-test', $rule['id']);
    }

    public function test_route_template_declaring_current_version_compiles_fine(): void
    {
        $doc = $this->baseRouteDoc();
        $doc['version'] = 1;

        $rule = $this->normalizeRoute($doc);

        self::assertSame('route-schema-test', $rule['id']);
    }

    public function test_route_template_declaring_a_future_version_is_refused(): void
    {
        $doc = $this->baseRouteDoc();
        $doc['version'] = 2;

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessageMatches('/schema/i');

        $this->normalizeRoute($doc);
    }
}
