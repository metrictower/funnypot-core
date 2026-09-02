<?php
declare(strict_types=1);
namespace Funnypot\Core\Support\Chrome;

use Funnypot\Core\Support\VisualPersona;

/**
 * A hand-authored lookalike of the wp-login.php screen — not a copy of WordPress markup, just close
 * enough in shape (centered card, a `login`-classed form, `log`/`pwd` fields) that the fake page reads
 * as "one more WP install" among the millions of real ones. The WP-shaped class names below are fixed
 * literals on purpose: for this skin, blending into the WP install-base fleet-wide *is* the anti-
 * fingerprint property, unlike GenericSkin where seed-derived CSS avoids a shared hash.
 */
final class WordpressSkin extends AbstractSkin
{
    /** The real wp-admin left-menu vocabulary, used only when the caller supplies no navItems. Fixed
     *  literals on purpose — blending into the WP install-base fleet-wide is this skin's anti-fingerprint
     *  property (same reasoning as the fixed login-card class names). */
    private const DEFAULT_MENU = [
        'Dashboard', 'Posts', 'Media', 'Pages', 'Comments',
        'Appearance', 'Plugins', 'Users', 'Tools', 'Settings',
    ];

    public function matches(string $path): bool
    {
        // "wp-" is a segment PREFIX, not a whole segment on its own — the real files it needs to
        // catch (wp-login.php, wp-admin, wp-content, wp-json, ...) all carry more than the bare token.
        return PathSegments::hasPrefixed($path, 'wp-');
    }

    public function key(): string
    {
        return 'wordpress';
    }

    public function render(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $siteRaw = $slots->appName() !== '' ? $slots->appName() : $persona->company();
        $site = $this->esc($siteRaw);
        $domain = $this->esc($persona->domain());

        $html = '<div id="login">';
        $html .= '<h1><a href="#">' . $site . '</a></h1>';

        $notice = $slots->heading() !== '' ? $slots->heading() : $slots->flash();
        if ($notice !== '') {
            $html .= '<div id="login_error">' . $this->esc($notice) . '</div>';
        }
        if ($slots->intro() !== '') {
            $html .= '<p class="message">' . $this->esc($slots->intro()) . '</p>';
        }

        // action is the pre-escaped request path; hrefs below are trusted literals, never model bytes.
        $html .= '<form name="loginform" id="loginform" class="login" action="' . $escapedPath . '" method="post">'
            . '<p class="login-username">'
            . '<label for="user_login">Username or Email Address</label>'
            . '<input type="text" name="log" id="user_login" class="input" size="20" autocapitalize="off">'
            . '</p>'
            . '<p class="login-password">'
            . '<label for="user_pass">Password</label>'
            . '<input type="password" name="pwd" id="user_pass" class="input" size="20">'
            . '</p>'
            . '<p class="forgetmenot">'
            . '<label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever"> Remember Me</label>'
            . '</p>'
            . '<p class="submit">'
            . '<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In">'
            . '</p>'
            . '</form>';

        $html .= '<p id="nav"><a href="#">Lost your password?</a></p>';
        $html .= '</div>';

        $html .= '<p class="footer">' . $domain;
        if ($slots->footerNote() !== '') {
            $html .= ' &middot; ' . $this->esc($slots->footerNote());
        }
        $html .= '</p>';

        return $this->document(
            $siteRaw . ' - Log In',
            $this->css(),
            $html,
            ' lang="en-US"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                . $this->wpMarkers($persona),
            ' class="login no-js"'
        );
    }

    /**
     * The authed wp-admin dashboard shell — a NEW public method, deliberately NOT a branch inside
     * render(): the LLM-tier skin router (app-side) calls render() for every wp-* path, so changing
     * render()'s semantics would silently move LLM-tier output. The decoy-session gate news up this
     * concrete class and calls renderAdmin() directly (mirroring how the gate news up PhpMyAdminSkin),
     * so this admin shell adds zero drift for the login-card consumer.
     *
     * Mirrors PhpMyAdminSkin::render(): a `#wpadminbar` top bar, an `#adminmenu` left column carrying
     * the real wp-admin menu vocabulary (slot-driven, else DEFAULT_MENU), an At-a-Glance card naming the
     * SAME wordpress.version/theme identity wpMarkers() emits, and the loot table via the inherited
     * tableHtml(). Every dynamic string routes through esc() (escape-by-construction). Menu links point
     * only at '#' (never an un-owned /wp-admin/*.php path that would fall through to unrelated corpus
     * bundles and break the story). Class names/menu labels are fixed WP literals — the intended blending
     * posture, verified fingerprint-safe by the gate's runtime FingerprintGuard verify-before-serve tail.
     */
    public function renderAdmin(PageSlots $slots, VisualPersona $persona, string $escapedPath, string $path = ''): string
    {
        $id = $persona->identity();
        $siteRaw = $slots->appName() !== '' ? $slots->appName() : $persona->company();
        $site = $this->esc($siteRaw);
        $adminUser = $this->esc($id->field('user.admin.username') ?? 'admin');
        $core = $this->esc($id->field('wordpress.version') ?? '6.4.3');
        $theme = $this->esc($id->field('wordpress.theme') ?? 'twentytwentyfour');

        $bar = '<div id="wpadminbar"><div class="ab-top">'
            . '<span class="ab-item ab-site">' . $site . '</span>'
            . '<span class="ab-item ab-howdy">Howdy, ' . $adminUser . '</span>'
            . '</div></div>';

        $menuItems = $slots->navItems() !== [] ? $slots->navItems() : self::DEFAULT_MENU;
        $menu = '<div id="adminmenuwrap"><ul id="adminmenu">';
        foreach ($menuItems as $item) {
            $menu .= '<li class="menu-top"><a class="menu-top" href="#">' . $this->esc($item) . '</a></li>';
        }
        $menu .= '</ul></div>';

        $main = '<div id="wpbody"><div id="wpbody-content">';
        $main .= '<h1 class="wp-heading-inline">Dashboard</h1>';
        $main .= '<div class="postbox" id="dashboard_right_now">'
            . '<h2 class="hndle">At a Glance</h2>'
            . '<div class="inside"><p>WordPress ' . $core . ' running the ' . $theme . ' theme.</p></div>'
            . '</div>';

        $table = $this->tableHtml($slots->tableCols(), $slots->tableRows(), ' class="wp-list-table widefat fixed striped users"');
        if ($table !== '') {
            $main .= '<div class="postbox" id="users_list">'
                . '<h2 class="hndle">Users</h2>'
                . '<div class="inside">' . $table . '</div>'
                . '</div>';
        }
        $main .= '</div></div>';

        $body = $bar . '<div id="wpwrap">' . $menu . $main . '</div>';

        return $this->document(
            "Dashboard \u{2039} " . $siteRaw . " \u{2014} WordPress",
            $this->adminCss(),
            $body,
            ' lang="en-US"',
            '<meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                . $this->wpMarkers($persona),
            ' class="wp-admin wp-core-ui"'
        );
    }

    /** wp-admin-flavoured chrome CSS: a top admin bar, a dark left menu column, and card `postbox`
     *  panels — resemblance to the real admin scheme, every hex nudged off WordPress's exact tokens. */
    private function adminCss(): string
    {
        return 'body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,sans-serif;background:#f0f0f1;color:#3c434a}'
            . '#wpadminbar{height:32px;background:#1d2429;color:#f0f0f1;font-size:13px}'
            . '#wpadminbar .ab-top{display:flex;align-items:center;justify-content:space-between;height:32px;padding:0 12px}'
            . '#wpadminbar .ab-item{line-height:32px}'
            . '#wpwrap{display:flex;min-height:calc(100vh - 32px)}'
            . '#adminmenuwrap{width:160px;background:#1d2429;flex:0 0 160px}'
            . '#adminmenu{list-style:none;margin:0;padding:0}'
            . '#adminmenu .menu-top{display:block}'
            . '#adminmenu a.menu-top{display:block;padding:8px 12px;color:#c3c4c7;text-decoration:none;font-size:14px}'
            . '#adminmenu a.menu-top:hover{background:#2c3338;color:#72aee6}'
            . '#wpbody{flex:1;min-width:0}'
            . '#wpbody-content{padding:16px 22px}'
            . '.wp-heading-inline{font-size:23px;font-weight:400;margin:6px 0 16px;color:#1d2327}'
            . '.postbox{background:#fff;border:1px solid #c3c4c7;border-radius:3px;margin-bottom:18px}'
            . '.postbox .hndle{margin:0;padding:8px 12px;border-bottom:1px solid #c3c4c7;font-size:14px;font-weight:600}'
            . '.postbox .inside{padding:10px 12px}'
            . '.wp-list-table{border-collapse:collapse;width:100%}'
            . '.wp-list-table th{background:#f6f7f7;text-align:left;padding:8px 10px;border-bottom:1px solid #c3c4c7;font-weight:600}'
            . '.wp-list-table td{padding:8px 10px;border-bottom:1px solid #f0f0f1}';
    }

    /**
     * The passive WordPress front-door markers a WP fingerprinter reads straight from the served
     * <head>: the generator meta, the REST API + oEmbed discovery links, and versioned
     * wp-includes / wp-content/themes asset references. These are ordinary WordPress output —
     * emitting them is the intended bait, not a scanner signature, so blending into the real WP
     * install-base is the anti-fingerprint property (same reasoning as the fixed WP class names).
     *
     * Every value is a fixed literal or a persona-derived version/theme/domain drawn from closed
     * pools (and a slug.tld domain), so nothing here is attacker-shaped; each is still escaped for
     * its attribute sink as defence in depth. One coherent version per deploy: the core version
     * pins the generator and the wp-includes asset ?ver=, while the theme stylesheet carries the
     * theme's own differently-shaped version — so the ?ver= values are never mechanically identical.
     */
    private function wpMarkers(VisualPersona $persona): string
    {
        $id = $persona->identity();
        $core = $this->esc($id->field('wordpress.version') ?? '6.4.3');
        $theme = $this->esc($id->field('wordpress.theme') ?? 'twentytwentyfour');
        $themeVer = $this->esc($id->field('wordpress.themeVersion') ?? '1.2');
        $oembed = $this->esc('/wp-json/oembed/1.0/embed?url=' . rawurlencode('https://' . $persona->domain() . '/'));

        return '<meta name="generator" content="WordPress ' . $core . '">'
            . '<link rel="https://api.w.org/" href="/wp-json/">'
            . '<link rel="alternate" type="application/json+oembed" href="' . $oembed . '&#038;format=json">'
            . '<link rel="alternate" type="text/xml+oembed" href="' . $oembed . '&#038;format=xml">'
            . '<link rel="stylesheet" id="dashicons-css" href="/wp-includes/css/dashicons.min.css?ver=' . $core . '" media="all">'
            . '<link rel="stylesheet" id="' . $theme . '-style-css" href="/wp-content/themes/' . $theme . '/style.css?ver=' . $themeVer . '" media="all">'
            . '<script src="/wp-includes/js/jquery/jquery.min.js?ver=' . $core . '"></script>';
    }

    private function css(): string
    {
        // Palette reads as a WP-style admin scheme (blue primary, red error, blue-grey neutrals) but
        // every hex is nudged off WordPress's exact default color-scheme tokens — resemblance, not reuse.
        return 'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
            . 'background:#eeeff0;font-family:sans-serif;color:#393f47}'
            . '#login{width:320px;padding:26px 24px;background:#fff;border:1px solid #d8d9db;border-radius:4px;'
            . 'box-shadow:0 1px 3px rgba(0,0,0,.08)}'
            . '#login h1{text-align:center;margin:0 0 20px}'
            . '#login h1 a{color:#393f47;text-decoration:none;font-size:1.3em}'
            . '#login_error{background:#faeff0;border-left:4px solid #d1393c;padding:10px 12px;margin-bottom:16px}'
            . '.message{background:#eef4fa;border-left:4px solid #6ba7e0;padding:10px 12px;margin-bottom:16px}'
            . '.login-username,.login-password{margin-bottom:14px}'
            . '#login label{display:block;margin-bottom:4px;font-size:.9em}'
            . '#login .input{width:100%;box-sizing:border-box;padding:6px 8px;border:1px solid #888b91;border-radius:3px}'
            . '.forgetmenot label{display:flex;align-items:center;gap:6px;font-size:.9em}'
            . '.button-primary{background:#1f6caa;color:#fff;border:1px solid #1f6caa;border-radius:3px;'
            . 'padding:8px 14px;cursor:pointer}'
            . '#nav{text-align:center;margin-top:14px;font-size:.9em}'
            . '#nav a{color:#1f6caa;text-decoration:none}'
            . '.footer{text-align:center;margin-top:16px;color:#60656c;font-size:.85em}';
    }
}
