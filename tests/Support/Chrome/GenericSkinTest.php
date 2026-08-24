<?php
declare(strict_types=1);
namespace Funnypot\Tests\Support\Chrome;

use Funnypot\Support\Chrome\GenericSkin;
use Funnypot\Support\Chrome\PageSlots;
use Funnypot\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class GenericSkinTest extends TestCase
{
    private function render(array $slots, int $seed = 5): string
    {
        return (new GenericSkin())->render(PageSlots::fromArray($slots), VisualPersona::fromSeed($seed), '/hr/portal');
    }

    public function test_produces_a_full_styled_document(): void
    {
        $html = $this->render(['app_name' => 'HR Portal', 'heading' => 'Users']);
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('<style>', $html);           // inline CSS, real chrome
        self::assertStringContainsString('HR Portal', $html);
        self::assertStringContainsString('</html>', $html);
    }

    public function test_escapes_model_values(): void
    {
        $html = $this->render(['heading' => '<img src=x onerror=alert(1)>']);
        self::assertStringNotContainsString('<img src=x onerror', $html);
        self::assertStringContainsString('&lt;img', $html);
    }

    /** Marker resolution happens once, upstream (PageSlots::resolveMarkers()), before a skin ever
     *  sees the slots — exercised here directly rather than through the app-side PageShellRenderer
     *  shell (which does not move to core). */
    public function test_marker_cells_become_persona_fakes(): void
    {
        $persona = VisualPersona::fromSeed(5);
        $slots = PageSlots::fromArray(['table' => ['cols' => ['User', 'Token'], 'rows' => [['m.hale', 'APITOKEN']]]])
            ->resolveMarkers($persona);
        $html = (new GenericSkin())->render($slots, $persona, '/hr/portal');
        self::assertStringNotContainsString('APITOKEN', $html);
        self::assertMatchesRegularExpression('/tok_[0-9a-f]{12}/', $html);
    }

    public function test_class_names_and_colors_are_seed_varied(): void
    {
        $a = $this->render(['heading' => 'X'], 1);
        $b = $this->render(['heading' => 'X'], 2);
        self::assertNotSame($a, $b, 'different seeds must yield different bytes (anti-fingerprint)');
    }
}
