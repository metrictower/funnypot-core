<?php
declare(strict_types=1);
namespace Funnypot\Tests\Support\Chrome;

use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\Chrome\WordpressSkin;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class WordpressSkinTest extends TestCase
{
    public function test_matches_wp_paths(): void
    {
        $s = new WordpressSkin();
        self::assertTrue($s->matches('/wp-login.php'));
        self::assertTrue($s->matches('/wp-admin'));
        self::assertFalse($s->matches('/hr/portal'));
    }

    public function test_key_is_wordpress(): void
    {
        self::assertSame('wordpress', (new WordpressSkin())->key());
    }

    public function test_resembles_wp_and_escapes(): void
    {
        $html = (new WordpressSkin())->render(
            PageSlots::fromArray(['heading' => '<x onerror=1>', 'app_name' => 'Blog']),
            VisualPersona::fromSeed(4), '/wp-login.php'
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('login', strtolower($html));   // resemblance marker
        self::assertStringNotContainsString('<x onerror', $html);       // escaping holds
    }
}
