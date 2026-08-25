<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\PhpMyAdminSkin;
use Funnypot\Core\Support\VisualPersona;
use PHPUnit\Framework\TestCase;

final class PhpMyAdminSkinTest extends TestCase
{
    public function test_matches_phpmyadmin_paths(): void
    {
        $s = new PhpMyAdminSkin();
        self::assertTrue($s->matches('/phpmyadmin/index.php'));
        self::assertTrue($s->matches('/pma/index.php'));
        self::assertTrue($s->matches('/PMA/index.php'));
        self::assertFalse($s->matches('/hr/portal'));
    }

    public function test_key_is_phpmyadmin(): void
    {
        self::assertSame('phpmyadmin', (new PhpMyAdminSkin())->key());
    }

    public function test_resembles_phpmyadmin_and_escapes(): void
    {
        $html = (new PhpMyAdminSkin())->render(
            PageSlots::fromArray([
                'heading' => '<x onerror=1>',
                'app_name' => 'DB Admin',
                'table' => ['cols' => ['id', 'name'], 'rows' => [['1', 'alice']]],
            ]),
            VisualPersona::fromSeed(4), '/phpmyadmin/index.php'
        );
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('phpmyadmin', strtolower($html)); // resemblance marker
        self::assertStringNotContainsString('<x onerror', $html);          // escaping holds
    }

    /** Fingerprint fix: the class-name prefix must be seed-derived (VisualPersona::classPrefix()),
     *  never the fixed 'pma-' literal — a byte-identical class vocabulary across every deployment
     *  would itself be a fleet-wide static tell. */
    public function test_class_prefix_is_seed_derived_not_a_fixed_pma_literal(): void
    {
        $slots = PageSlots::fromArray(['heading' => 'Users']);
        $skin = new PhpMyAdminSkin();

        $personaA = VisualPersona::fromSeed(1);
        $personaB = VisualPersona::fromSeed(2);
        $htmlA = $skin->render($slots, $personaA, '/pma/index.php');
        $htmlB = $skin->render($slots, $personaB, '/pma/index.php');

        self::assertStringNotContainsString('class="pma-', $htmlA, 'no fixed pma- literal may survive the move into public core');
        self::assertStringContainsString('class="' . $personaA->classPrefix() . '-topbar"', $htmlA);
        self::assertStringContainsString('class="' . $personaB->classPrefix() . '-topbar"', $htmlB);
        self::assertNotSame($htmlA, $htmlB, 'two different seeds must render two different class vocabularies');
    }

    /** Fingerprint fix: the "server version" banner is routed through PersonaIdentity::productVersion()
     *  (via VisualPersona::identity()), not a locally-hardcoded VERSION_POOL — so a future core-template
     *  tier reading the same PersonaIdentity for this deployment claims the identical version string. */
    public function test_version_banner_matches_persona_identity_product_version(): void
    {
        $persona = VisualPersona::fromSeed(9);
        $html = (new PhpMyAdminSkin())->render(PageSlots::fromArray([]), $persona, '/pma/index.php');

        $expected = $persona->identity()->productVersion('mysql');
        self::assertStringContainsString($expected, $html);
    }

    /** Agent B's ask: the left-hand table tree is slot-driven (navItems), not a hardcoded list, so a
     *  mock-authed render can fill it with real table names (e.g. FakeRecords' users/sessions/...). */
    public function test_left_tree_is_slot_driven_from_nav_items(): void
    {
        $persona = VisualPersona::fromSeed(2);
        $slots = PageSlots::trusted('', '', '', '', ['users', 'password_resets', 'api_keys', 'sessions', 'orders']);
        $html = (new PhpMyAdminSkin())->render($slots, $persona, '/pma/index.php');

        foreach (['users', 'password_resets', 'api_keys', 'sessions', 'orders'] as $table) {
            self::assertStringContainsString('>' . $table . '<', $html);
        }
        // the unfilled default vocabulary must NOT leak in alongside the slot-driven one
        self::assertStringNotContainsString('>options<', $html);
        self::assertStringNotContainsString('>logs<', $html);
    }

    /** With no navItems supplied (e.g. an LLM page that never filled the slot), the tree still shows
     *  a plausible default table vocabulary rather than an empty tree. */
    public function test_left_tree_falls_back_to_default_tables_when_no_slot_data(): void
    {
        $persona = VisualPersona::fromSeed(2);
        $html = (new PhpMyAdminSkin())->render(PageSlots::fromArray([]), $persona, '/pma/index.php');
        self::assertStringContainsString('>users<', $html);
        self::assertStringContainsString('>sessions<', $html);
    }
}
