<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Support\Chrome\Esc;
use PHPUnit\Framework\TestCase;

final class EscTest extends TestCase
{
    public function test_escapes_html_and_quotes(): void
    {
        self::assertSame('&lt;img onerror=x&gt;', Esc::text('<img onerror=x>'));
        self::assertSame('a&quot;b&#039;c', Esc::attr('a"b\'c'));
    }
}
