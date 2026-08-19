<?php

declare(strict_types=1);

namespace Funnypot\Tests\Rules;

use Funnypot\Rules\PhpLiteralValidator;
use Funnypot\Rules\PhpLiteralViolation;
use PHPUnit\Framework\TestCase;

/**
 * The pre-`require` gate. The two properties that matter: it ACCEPTS the real compiled
 * artifacts this package ships (a false reject would break every legitimate update), and
 * it REJECTS anything that could execute on load (a false accept is the RCE this whole
 * mechanism exists to prevent).
 */
final class PhpLiteralValidatorTest extends TestCase
{
    private function validator(): PhpLiteralValidator
    {
        return new PhpLiteralValidator();
    }

    private function compiled(string $name): string
    {
        return dirname(__DIR__, 2) . '/resources/compiled/' . $name;
    }

    /** @dataProvider realArtifacts */
    public function test_accepts_the_real_compiled_artifacts(string $file): void
    {
        $path = $this->compiled($file);
        self::assertFileExists($path);
        self::assertTrue(
            $this->validator()->isValidFile($path),
            "expected the shipped artifact {$file} to validate as a pure literal"
        );
        // validateFile must not throw.
        $this->validator()->validateFile($path);
        $this->addToAssertionCount(1);
    }

    /** @return array<string,array{0:string}> */
    public static function realArtifacts(): array
    {
        return [
            'nuclei index' => ['nuclei-index.full.php'],
            'attack rules' => ['funnypot-attack.php'],
            'route rules' => ['funnypot-routes.php'],
            'route index fragment' => ['funnypot-routes-index.php'],
        ];
    }

    /** @dataProvider validLiterals */
    public function test_accepts_pure_literals(string $code): void
    {
        self::assertTrue($this->validator()->isValid($code), $code);
    }

    /** @return array<string,array{0:string}> */
    public static function validLiterals(): array
    {
        return [
            'empty short array' => ["<?php return [];"],
            'empty long array' => ["<?php return array();"],
            'with declare' => ["<?php\n\ndeclare(strict_types=1);\n\nreturn array('a' => 1);"],
            'nested + scalars' => ["<?php return ['n' => 1, 'f' => 1.5, 'b' => true, 'z' => null, 'x' => false, 'k' => ['y' => -2]];"],
            'trailing comma + comment' => ["<?php // hi\nreturn [\n  'a' => 1,\n];\n"],
            // A rule regex/body may legitimately contain text that LOOKS like code — it is
            // inside a quoted string, one token, and must not be flagged.
            'dangerous-looking data' => ["<?php return ['body' => 'system(\\'id\\'); <?php eval(1); `ls`'];"],
            'signed and float' => ["<?php return array(0 => -1, 1 => +2, 2 => 3.14);"],
            // var_export renders a binary matcher value as concatenated string-literal fragments.
            'binary string concat' => ["<?php return ['magic' => 'SQLite format 3' . \"\\0\" . 'x'];"],
        ];
    }

    /** @dataProvider poisoned */
    public function test_rejects_executable_payloads(string $code, string $label): void
    {
        self::assertFalse($this->validator()->isValid($code), "should reject: {$label}");
        $this->expectException(PhpLiteralViolation::class);
        $this->validator()->validate($code, $label);
    }

    /** @return array<string,array{0:string,1:string}> */
    public static function poisoned(): array
    {
        return [
            'function call' => ["<?php return ['x' => system('id')];", 'system() call'],
            'bare call before return' => ["<?php system('id'); return [];", 'side effect before return'],
            'include' => ["<?php return include 'evil.php';", 'include expression'],
            'require' => ["<?php require 'x'; return [];", 'require statement'],
            'eval' => ["<?php return ['x' => eval('return 1;')];", 'eval'],
            'variable' => ["<?php \$x = 1; return [\$x];", 'variable'],
            'object state' => ["<?php return \\Foo::__set_state(['a' => 1]);", '::__set_state'],
            'new object' => ["<?php return [new \\stdClass()];", 'new'],
            'backtick' => ["<?php return ['x' => `ls`];", 'shell backtick'],
            'concat call' => ["<?php return ['x' => 'a' . phpinfo()];", 'concat + call'],
            'second statement' => ["<?php return []; phpinfo();", 'trailing statement'],
            'echo open tag' => ["<?= system('id') ?>", 'short echo tag'],
            'leading html' => ["evil<?php return [];", 'inline HTML before <?php'],
            'close tag output' => ["<?php return []; ?><script>alert(1)</script>", 'close tag then output'],
            'declare with side effect' => ["<?php declare(ticks=1); register_tick_function('x'); return [];", 'ticks declare'],
            'heredoc-free constant' => ["<?php return [PHP_INT_MAX];", 'global constant'],
        ];
    }

    public function test_unreadable_file_is_invalid(): void
    {
        self::assertFalse($this->validator()->isValidFile('/no/such/artifact.php'));
    }
}
