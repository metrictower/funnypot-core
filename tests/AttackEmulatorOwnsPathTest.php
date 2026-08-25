<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Template\TemplateAttackEmulator;
use PHPUnit\Framework\TestCase;

/**
 * The emulator folds every rule's owns_path into a membership set at construction; ownsPath()
 * answers via the shared ownership key, so case/trailing-slash variants of an owned path match and
 * an unowned path does not.
 */
final class AttackEmulatorOwnsPathTest extends TestCase
{
    private function emulator(): TemplateAttackEmulator
    {
        // Two hand rules: one owns /xmlrpc.php, one owns nothing.
        return new TemplateAttackEmulator([
            [
                'id' => 'attack-owns',
                'match' => [['in' => 'path', 'regex' => '(?:^|/)xmlrpc\.php(?:/|$)']],
                'response' => ['headers' => [], 'body' => 'x'],
                'status' => 200,
                'owns_path' => ['/xmlrpc.php'],
            ],
            [
                'id' => 'attack-plain',
                'match' => [['in' => 'path', 'regex' => '/other']],
                'response' => ['headers' => [], 'body' => 'y'],
                'status' => 200,
            ],
        ]);
    }

    public function test_owns_declared_path_and_its_variants(): void
    {
        $e = $this->emulator();
        self::assertTrue($e->ownsPath('/xmlrpc.php'));
        self::assertTrue($e->ownsPath('/XMLRPC.PHP'));
        self::assertTrue($e->ownsPath('/xmlrpc.php/'));
    }

    public function test_does_not_own_unclaimed_paths(): void
    {
        $e = $this->emulator();
        self::assertFalse($e->ownsPath('/other'));
        self::assertFalse($e->ownsPath('/xmlrpc.phpx'));
        self::assertFalse($e->ownsPath('/'));
    }
}
