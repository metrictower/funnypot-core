<?php
declare(strict_types=1);
namespace Funnypot\Core\Tests\Support\Chrome;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
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

    // --- FP-0491: renderLockout() — the login page carrying a fake lockout notice (NOT render()) --

    /** The lockout page is the login card plus a generic "too many attempts / try again in N minutes"
     *  notice — fails if the notice is absent (i.e. it rendered the plain login page). */
    public function test_lockout_page_served(): void
    {
        $html = (new WordpressSkin())->renderLockout(
            PageSlots::fromArray(['app_name' => 'Blog']), VisualPersona::fromSeed(4), '/wp-login.php', 4
        );

        $lower = strtolower($html);
        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('name="loginform"', $html);           // still the login card
        self::assertStringContainsString('id="login_error"', $html);           // the notice slot is filled
        self::assertStringContainsString('too many failed login attempts', $lower);
        self::assertStringContainsString('try again in', $lower);
        self::assertMatchesRegularExpression('/try again in \d+ minutes/', $lower);
    }

    /** Countdown is deterministic from the seed alone (stateless): same seed -> same N, and different
     *  seeds vary within the fixed list. Fails if the countdown reads time/state (e.g. rand()). */
    public function test_countdown_deterministic(): void
    {
        $skin = new WordpressSkin();
        $extract = static function (string $html): int {
            self::assertSame(1, preg_match('/try again in (\d+) minutes/', strtolower($html), $m));
            return (int) $m[1];
        };

        $a = $extract($skin->renderLockout(PageSlots::fromArray([]), VisualPersona::fromSeed(4), '/wp-login.php', 4));
        $b = $extract($skin->renderLockout(PageSlots::fromArray([]), VisualPersona::fromSeed(4), '/wp-login.php', 4));
        self::assertSame($a, $b, 'same seed must yield the same countdown');

        // Different seeds de-correlate: sweep a range and confirm at least two distinct values appear,
        // and every value comes from the fixed plausible-minutes list.
        $allowed = [5, 7, 9, 11, 13, 15, 17, 19, 23];
        $seen = [];
        for ($seed = 0; $seed < 40; $seed++) {
            $n = $extract($skin->renderLockout(PageSlots::fromArray([]), VisualPersona::fromSeed($seed), '/wp-login.php', $seed));
            self::assertContains($n, $allowed, "seed {$seed}: countdown outside the fixed list");
            $seen[$n] = true;
        }
        self::assertGreaterThan(1, count($seen), 'different seeds must produce more than one countdown value');
    }

    /** The lockout body is a text/html login document and still escapes hostile slot values. */
    public function test_lockout_content_type_and_escaping(): void
    {
        $html = (new WordpressSkin())->renderLockout(
            PageSlots::fromArray(['app_name' => '<x onerror=1>']), VisualPersona::fromSeed(6), '/wp-login.php', 6
        );

        self::assertStringStartsWith('<!doctype html>', $html);
        self::assertStringContainsString('charset', strtolower($html));
        self::assertStringNotContainsString('<x onerror', $html);   // esc() holds on the login card
    }

    /** Fingerprint-safe: FingerprintGuard clean AND explicitly no `llar` token (not denylisted) and no
     *  bare six-digit CRS rule id. Covers realistic and taunt copy. */
    public function test_lockout_fingerprint_safe(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $skin = new WordpressSkin();
        $headers = ['Content-Type' => 'text/html; charset=UTF-8'];

        foreach ([false, true] as $taunt) {
            for ($seed = 0; $seed < 12; $seed++) {
                $html = $skin->renderLockout(PageSlots::fromArray(['app_name' => 'Blog']), VisualPersona::fromSeed($seed), '/wp-login.php', $seed, $taunt);
                $guard->assertResponseClean($html, $headers, 'wp-lockout');
                self::assertStringNotContainsString('llar', strtolower($html), "seed {$seed} taunt=" . ($taunt ? '1' : '0'));
                self::assertDoesNotMatchRegularExpression('/\b9\d{5}\b/', $html, "seed {$seed} taunt=" . ($taunt ? '1' : '0'));
            }
        }
    }

    /** The taunt variant still renders a login-card lockout page with a notice and passes the guard. */
    public function test_lockout_taunt_variant(): void
    {
        $html = (new WordpressSkin())->renderLockout(
            PageSlots::fromArray(['app_name' => 'Blog']), VisualPersona::fromSeed(8), '/wp-login.php', 8, true
        );

        self::assertStringContainsString('name="loginform"', $html);
        self::assertStringContainsString('id="login_error"', $html);
        self::assertMatchesRegularExpression('/\d+ minutes/', strtolower($html));
        FingerprintGuard::fromPackage()->assertResponseClean($html, ['Content-Type' => 'text/html; charset=UTF-8'], 'wp-lockout-taunt');
    }

    /** renderLockout() is a SEPARATE method: it must not disturb the plain login-card render() output. */
    public function test_lockout_does_not_change_the_login_card_render(): void
    {
        $skin = new WordpressSkin();
        $login = $skin->render(PageSlots::fromArray(['app_name' => 'Blog']), VisualPersona::fromSeed(5), '/wp-login.php');
        self::assertStringNotContainsString('too many failed login attempts', strtolower($login));
    }
}
