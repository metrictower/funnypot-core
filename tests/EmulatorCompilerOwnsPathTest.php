<?php

declare(strict_types=1);

namespace Funnypot\Tests;

use Funnypot\Compiler\EmulatorCompiler;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * The compiler canonicalizes a template's owns_path entries (lower-case, trailing slash stripped)
 * and emits them as rule['owns_path']. A template with no owns_path emits no key.
 */
final class EmulatorCompilerOwnsPathTest extends TestCase
{
    /** Drive the private normalize() with a minimal valid doc (no `expect:` => marker check skipped). */
    private function normalizeRule(array $doc): array
    {
        $compiler = new EmulatorCompiler();
        $method = new ReflectionMethod($compiler, 'normalize');
        $method->setAccessible(true);

        return $method->invoke($compiler, $doc, 'owns-test.yaml');
    }

    private function baseDoc(): array
    {
        return [
            'id' => 'attack-owns-test',
            'severity' => 'high',
            'tags' => ['attack', 'test'],
            'status' => 200,
            'match' => [['in' => 'path', 'regex' => 'never-matches-anything']],
            'response' => ['body' => 'x'],
        ];
    }

    public function test_owns_path_is_canonicalized_and_emitted(): void
    {
        $doc = $this->baseDoc();
        $doc['owns_path'] = ['/XMLRPC.PHP', '/foo/bar/'];

        $rule = $this->normalizeRule($doc);

        self::assertSame(['/xmlrpc.php', '/foo/bar'], $rule['owns_path']);
    }

    public function test_single_string_owns_path_is_coerced_to_list(): void
    {
        $doc = $this->baseDoc();
        $doc['owns_path'] = '/xmlrpc.php';

        $rule = $this->normalizeRule($doc);

        self::assertSame(['/xmlrpc.php'], $rule['owns_path']);
    }

    public function test_absent_owns_path_emits_no_key(): void
    {
        $rule = $this->normalizeRule($this->baseDoc());

        self::assertArrayNotHasKey('owns_path', $rule);
    }
}
