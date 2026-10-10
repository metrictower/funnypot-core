<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Executes scripts/ci/check-php73-syntax.php against the real src/ tree and against scratch
 * fixtures, proving each flagged construct trips the gate and that 7.3-valid look-alikes do not.
 * The gate reads newer token ids, so it runs on an 8.x host; on 7.3 the parser itself is the gate.
 */
final class Php73SyntaxGateTest extends TestCase
{
    private const SCRIPT = __DIR__ . '/../scripts/ci/check-php73-syntax.php';

    /** @var list<string> */
    private $tmp = [];

    protected function setUp(): void
    {
        if (PHP_VERSION_ID < 80000) {
            self::markTestSkipped('the gate tokenizes with 8.x token ids');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->tmp as $path) {
            @unlink($path);
        }
    }

    public function test_src_tree_is_clean(): void
    {
        [$code, $out] = $this->run_gate([]);
        self::assertSame(0, $code, $out);
    }

    /** @return array<string,array{string}> */
    public function post73Snippets(): array
    {
        return [
            'coalesce assign' => ['$a["k"] ??= 1;'],
            'arrow fn' => ['$f = fn($x) => $x;'],
            'match' => ['$y = match ($x) { 1 => 2, default => 3 };'],
            'nullsafe' => ['$y = $x?->foo;'],
            'typed property' => ['class A { private int $n = 0; }'],
            'nullable typed static property' => ['class A { public static ?string $s = null; }'],
            'promotion' => ['class A { public function __construct(private $x) {} }'],
            'readonly' => ['class A { public readonly $x; }'],
            'enum' => ['enum Suit { case H; }'],
            'attribute' => ['#[Attr] function f() {}'],
            'numeric separator' => ['$n = 1_000;'],
            'union param' => ['function f(int|string $x) {}'],
            'mixed param' => ['function f(mixed $x) {}'],
            'union return' => ['function f(): int|false { return 1; }'],
            'static return' => ['class A { public function f(): static { return $this; } }'],
            'catch no var' => ['try {} catch (\Exception) {}'],
            'first-class callable' => ['$f = strlen(...);'],
            'object class' => ['$c = $o::class;'],
            'str_contains' => ['$b = str_contains($h, "x");'],
            'qualified str_starts_with' => ['$b = \str_starts_with($h, "x");'],
        ];
    }

    /** @dataProvider post73Snippets */
    public function test_flags_post_73_construct(string $snippet): void
    {
        [$code, $out] = $this->run_gate([$this->fixture($snippet)]);
        self::assertSame(1, $code, $out);
        self::assertStringContainsString('is not PHP 7.3-compatible', $out);
    }

    public function test_allows_73_valid_look_alikes(): void
    {
        $snippet = implode("\n", [
            'use function strlen;',
            'class A {',
            '    private static $cache = [];',
            '    public $plain;',
            '    var $old;',
            '    public const C = 1;',
            '    final public static function match(?string $s, array $a = [], callable $c = null): ?self { return null; }',
            '    public function f(self $x, int ...$rest): void {}',
            '}',
            '$a = $a ?? 1;',
            '$m = A::match(null);',
            '$m = $o->match();',
            '$m = $o->str_contains();',
            '$x = function ($v) use ($a): int { return 1; };',
            '$k = A::class;',
            'try {} catch (\Exception $e) {}',
            '$n = 1000 | 2;',
            '// str_contains($a, $b) ??= fn() in a comment',
        ]);
        [$code, $out] = $this->run_gate([$this->fixture($snippet)]);
        self::assertSame(0, $code, $out);
    }

    private function fixture(string $body): string
    {
        $path = (string) tempnam(sys_get_temp_dir(), 'php73gate');
        file_put_contents($path, "<?php\n" . $body . "\n");
        $this->tmp[] = $path;
        return $path;
    }

    /**
     * @param list<string> $args
     * @return array{int,string}
     */
    private function run_gate(array $args): array
    {
        $cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(self::SCRIPT);
        foreach ($args as $a) {
            $cmd .= ' ' . escapeshellarg($a);
        }
        exec($cmd . ' 2>&1', $lines, $code);
        return [$code, implode("\n", $lines)];
    }
}
