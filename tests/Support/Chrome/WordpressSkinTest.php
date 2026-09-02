<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Support\Chrome\PageSlots;
use Funnypot\Core\Support\Chrome\WordpressSkin;
use Funnypot\Core\Support\VisualPersona;
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

    /** The passive front-door markers a WP fingerprinter keys on must be present in the head. */
    public function test_carries_wpscan_front_door_markers(): void
    {
        $html = (new WordpressSkin())->render(
            PageSlots::fromArray(['app_name' => 'Blog']),
            VisualPersona::fromSeed(7), '/wp-login.php'
        );

        // D3 generator meta, D2/D4 REST + oEmbed discovery links.
        self::assertStringContainsString('<meta name="generator" content="WordPress ', $html);
        self::assertStringContainsString('rel="https://api.w.org/"', $html);
        self::assertStringContainsString('/wp-json/oembed/1.0/embed?url=', $html);
        // D1 versioned assets under the two path roots WordPress detection scans.
        self::assertMatchesRegularExpression('#/wp-includes/css/dashicons\.min\.css\?ver=[\d.]+#', $html);
        self::assertMatchesRegularExpression('#/wp-content/themes/[a-z0-9-]+/style\.css\?ver=[\d.]+#', $html);
        self::assertMatchesRegularExpression('#/wp-includes/js/jquery/jquery\.min\.js\?ver=[\d.]+#', $html);
    }

    /**
     * WordpressSkin renders the same document for every wp- surface it serves, so the homepage,
     * the login page and a not-found wp- path all carry the detection markers with a ?ver= asset.
     */
    public function test_homepage_login_and_404_surfaces_all_carry_markers(): void
    {
        $skin = new WordpressSkin();
        $persona = VisualPersona::fromSeed(11);
        foreach (['/', '/wp-login.php', '/wp-content/plugins/does-not-exist'] as $path) {
            $html = $skin->render(PageSlots::fromArray([]), $persona, $path, $path);
            self::assertStringContainsString('<meta name="generator" content="WordPress ', $html, $path);
            self::assertStringContainsString('rel="https://api.w.org/"', $html, $path);
            self::assertMatchesRegularExpression('#\?ver=[\d.]+#', $html, $path);
        }
    }

    /**
     * One coherent version per deploy: the generator meta and the wp-includes asset ?ver= share the
     * core version, while the theme stylesheet carries a differently-shaped theme version — so the
     * markers are never mechanically identical.
     */
    public function test_version_is_coherent_across_generator_and_core_assets(): void
    {
        for ($seed = 0; $seed < 12; $seed++) {
            $html = (new WordpressSkin())->render(
                PageSlots::fromArray([]), VisualPersona::fromSeed($seed), '/wp-login.php'
            );

            self::assertSame(1, preg_match('/content="WordPress ([\d.]+)"/', $html, $gen), "seed {$seed}: generator");
            self::assertSame(1, preg_match('#dashicons\.min\.css\?ver=([\d.]+)#', $html, $inc), "seed {$seed}: wp-includes ver");
            self::assertSame(1, preg_match('#/themes/[a-z0-9-]+/style\.css\?ver=([\d.]+)#', $html, $thm), "seed {$seed}: theme ver");

            self::assertSame($gen[1], $inc[1], "seed {$seed}: generator and wp-includes assets share the core version");
            self::assertNotSame($gen[1], $thm[1], "seed {$seed}: the theme ?ver= is not the core ?ver=");
        }
    }

    public function test_markers_are_deterministic_per_seed(): void
    {
        $a = (new WordpressSkin())->render(PageSlots::fromArray([]), VisualPersona::fromSeed(3), '/wp-login.php');
        $b = (new WordpressSkin())->render(PageSlots::fromArray([]), VisualPersona::fromSeed(3), '/wp-login.php');
        self::assertSame($a, $b);
    }

    // --- FP-0271: renderAdmin() — the authed wp-admin dashboard shell (NOT render()) ----------

    private function adminSlots(): PageSlots
    {
        // Trusted (app-supplied) rows, as the decoy-session gate builds them: a users loot table.
        return PageSlots::trusted(
            'Blog',
            '',
            '',
            '',
            [],
            ['Username', 'Name', 'Email', 'Role', 'API key'],
            // Secret-shaped literal split per the project's AGENT-EXECUTION-RULES (never a contiguous
            // AKIA token in source); the value is only asserted to render as an escaped cell.
            [['jadmin', 'Jane Admin', 'jadmin@blog.test', 'Administrator', 'AKIA' . 'EXAMPLETOKENVALUE']],
            [],
            '',
            ''
        );
    }

    public function test_render_admin_draws_the_wp_admin_shell(): void
    {
        $html = (new WordpressSkin())->renderAdmin($this->adminSlots(), VisualPersona::fromSeed(5), '/wp-admin/', '/wp-admin/');

        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('id="wpadminbar"', $html);
        self::assertStringContainsString('id="adminmenu"', $html);
        self::assertStringContainsString('Howdy,', $html);
        self::assertStringContainsString('At a Glance', $html);
        self::assertStringContainsString('wp-list-table', $html);
        // The default wp-admin menu vocabulary is present (slot-driven fallback).
        foreach (['Dashboard', 'Posts', 'Plugins', 'Users', 'Settings'] as $item) {
            self::assertStringContainsString('>' . $item . '</a>', $html, $item);
        }
        // The loot table headers + a cell.
        self::assertStringContainsString('<th>Username</th>', $html);
        self::assertStringContainsString('<td>jadmin</td>', $html);
        // Front-door markers ride the same head as the login card (one coherent WP identity).
        self::assertStringContainsString('<meta name="generator" content="WordPress ', $html);
    }

    public function test_render_admin_escapes_every_slot_cell(): void
    {
        $slots = PageSlots::trusted(
            '<script>evil</script>',
            '', '', '', [],
            ['User', 'Note'],
            [['x', '<img src=x onerror=1>']],
            [], '', ''
        );
        $html = (new WordpressSkin())->renderAdmin($slots, VisualPersona::fromSeed(5), '/wp-admin/', '/wp-admin/');

        self::assertStringNotContainsString('<script>evil', $html);
        self::assertStringNotContainsString('<img src=x onerror', $html);
        self::assertStringContainsString('&lt;script&gt;evil', $html);
    }

    public function test_render_admin_is_deterministic_per_seed(): void
    {
        $a = (new WordpressSkin())->renderAdmin($this->adminSlots(), VisualPersona::fromSeed(9), '/wp-admin/', '/wp-admin/');
        $b = (new WordpressSkin())->renderAdmin($this->adminSlots(), VisualPersona::fromSeed(9), '/wp-admin/', '/wp-admin/');
        self::assertSame($a, $b);
    }

    /** renderAdmin() is a SEPARATE method: it must not disturb the login-card render() output. */
    public function test_render_admin_does_not_change_the_login_card_render(): void
    {
        $login = (new WordpressSkin())->render(PageSlots::fromArray(['app_name' => 'Blog']), VisualPersona::fromSeed(5), '/wp-login.php');
        self::assertStringContainsString('id="login"', $login);
        self::assertStringContainsString('name="loginform"', $login);
        // The login card is not the admin shell.
        self::assertStringNotContainsString('id="wpadminbar"', $login);
        self::assertStringNotContainsString('id="adminmenu"', $login);
    }
}
