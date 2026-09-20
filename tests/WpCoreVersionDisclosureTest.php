<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use PHPUnit\Framework\TestCase;

/**
 * FP-0394 — WordPress core version-disclosure suite. One deploy-stable
 * {{persona.wordpress.version}} is rendered into every WP version channel so a core fingerprinter
 * reads one consistent version across them (the ticket's "prevent scanner discrepancies" invariant).
 *
 * Drives the REAL engine over the FULL compiled index (nuclei-index.full.php) + the compiled attack
 * file (the NextjsRscPersonaTest pattern), so classify()'s owns_path override + the route/persona
 * lottery run on the true serve path, not a stub. The 6-route hand fixture would prove nothing — the
 * surfaces under test (and the existing degenerate `wordpress` `/` variant) live only in the full
 * corpus.
 *
 * Ceiling is `critical` — prod's ceiling, and the level at which the wp-install (critical) surface
 * serves. At the default `high` ceiling the critical install surface is suppressed exactly as the
 * existing critical store bundle already is (no regression), so it is not exercised here.
 *
 * Two seed classes are exercised:
 *   $seedWp    — served `/` is the EXISTING degenerate `wordpress` variant (w=100, the dominant slice
 *                v1 never tested): T-EXIST asserts the five DEDICATED channels are coherent there.
 *   $seedRoute — served `/` is the new `route-wordpress` new_page (w=8): full six-channel coherence.
 * plus a non-WP-`/` guard and a compiled-artifact falsifier.
 */
final class WpCoreVersionDisclosureTest extends TestCase
{
    private const INDEX = __DIR__ . '/../resources/compiled/nuclei-index.full.php';
    private const ATTACK = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    /** @var array<string,mixed>|null */
    private static $index;

    /** @return array<string,mixed> */
    private function index(): array
    {
        if (self::$index === null) {
            self::$index = require self::INDEX;
        }

        return self::$index;
    }

    /** A full engine pinned to one persona seed, attack tier live, `/` gate + probe signature open. */
    private function engine(string $seed): Honeypot
    {
        return new Honeypot(new PhpArrayStore($this->index()), new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },   // gate open
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; }, // seedFor
            'coherent',
            'realistic',
            'critical',  // prod ceiling — the wp-install (critical) surface serves
            65536,
            0,
            0,
            true,   // attackEmulation ⇒ owns_path override runs
            null,
            null,
            static function (RequestContext $r): bool { return true; },   // probeSignature ⇒ root '/' serves
            '',
            [],
            true
        ));
    }

    private function bodyOf(Honeypot $e, string $method, string $path, string $query = ''): string
    {
        $r = $e->respond(new RequestContext($method, $path, $query));

        return $r === null ? '' : $r->body;
    }

    /** The served `/` is the corpus's existing degenerate `wordpress` variant (a login/enum witness, no homepage marker). */
    private function servedExistingWp(Honeypot $e): bool
    {
        $b = $this->bodyOf($e, 'GET', '/');

        return strpos($b, 'Username or Email Address') !== false
            && strpos($b, '<meta name="generator" content="WordPress') === false;
    }

    /** The served `/` is the new route-wordpress homepage shell. */
    private function servedRouteWp(Honeypot $e): bool
    {
        $b = $this->bodyOf($e, 'GET', '/');

        return strpos($b, '<meta name="generator" content="WordPress') !== false
            && strpos($b, 'wp-emoji-release.min.js') !== false;
    }

    /** The served `/` is neither WP persona (used for the poly-stack non-WP guard). */
    private function servedNonWp(Honeypot $e): bool
    {
        $b = $this->bodyOf($e, 'GET', '/');

        return strpos($b, 'Username or Email Address') === false
            && strpos($b, '<meta name="generator" content="WordPress') === false;
    }

    /** @param callable(Honeypot):bool $pred */
    private function firstSeed(callable $pred, string $what, int $max = 6000): string
    {
        for ($s = 0; $s <= $max; $s++) {
            if ($pred($this->engine((string) $s))) {
                return (string) $s;
            }
        }
        self::fail("no seed in 0..{$max} whose served / is {$what}");
    }

    /** The version disclosed at /readme.html — the single V every other channel must match. */
    private function versionFromReadme(Honeypot $e): string
    {
        $b = $this->bodyOf($e, 'GET', '/readme.html');
        self::assertSame(1, preg_match('/<p>Version ([0-9][0-9.]*)<\/p>/', $b, $m), 'readme must disclose a dotted version');

        return $m[1];
    }

    // --- T-EXIST (the must-fix guard): coherence on the EXISTING degenerate `wordpress` `/` deploy ---

    public function test_t_exist_five_dedicated_channels_cohere_on_existing_wordpress_seed(): void
    {
        $seed = $this->firstSeed([$this, 'servedExistingWp'], 'the existing degenerate wordpress variant');
        $e = $this->engine($seed);
        $v = $this->versionFromReadme($e);

        $readme = $this->bodyOf($e, 'GET', '/readme.html');
        $opml = $this->bodyOf($e, 'GET', '/wp-links-opml.php');
        $feed = $this->bodyOf($e, 'GET', '/feed/');
        $install = $this->bodyOf($e, 'GET', '/wp-admin/install.php');
        $rss2 = $this->bodyOf($e, 'GET', '/', 'feed=rss2');

        // All five dedicated channels disclose the one V — even though `/` itself is degenerate here.
        self::assertStringContainsString('Version ' . $v, $readme, 'readme discloses V');
        self::assertStringContainsString('generator="WordPress/' . $v . '"', $opml, 'opml discloses V');
        self::assertStringContainsString('https://wordpress.org/?v=' . $v, $feed, 'feed discloses V');
        self::assertStringContainsString('install.min.css?ver=' . $v, $install, 'install discloses V');
        self::assertStringContainsString('https://wordpress.org/?v=' . $v, $rss2, 'rss2 discloses V');

        // The residual is a GAP, not a CONTRADICTION: the degenerate homepage advertises no ?v= at all,
        // so a cross-checking scanner reads nothing there (non-detection), never a conflicting version.
        $home = $this->bodyOf($e, 'GET', '/');
        self::assertStringNotContainsString('wordpress.org/?v=', $home, 'degenerate homepage advertises no generator version');
        self::assertStringNotContainsString('?ver=', $home, 'degenerate homepage advertises no versioned asset link');
    }

    // --- A1 full six-channel coherence on the route-wordpress homepage deploy ----------------------

    public function test_a1_all_six_channels_cohere_on_route_wordpress_seed(): void
    {
        $seed = $this->firstSeed([$this, 'servedRouteWp'], 'route-wordpress');
        $e = $this->engine($seed);
        $v = $this->versionFromReadme($e);

        $home = $this->bodyOf($e, 'GET', '/');
        self::assertStringContainsString('<meta name="generator" content="WordPress ' . $v . '"', $home, 'homepage generator meta = V');
        self::assertStringContainsString('wp-emoji-release.min.js?ver=' . $v, $home, 'homepage emoji asset = V');

        self::assertStringContainsString('generator="WordPress/' . $v . '"', $this->bodyOf($e, 'GET', '/wp-links-opml.php'));
        self::assertStringContainsString('https://wordpress.org/?v=' . $v, $this->bodyOf($e, 'GET', '/feed/'));
        self::assertStringContainsString('install.min.css?ver=' . $v, $this->bodyOf($e, 'GET', '/wp-admin/install.php'));
        self::assertStringContainsString('https://wordpress.org/?v=' . $v, $this->bodyOf($e, 'GET', '/', 'feed=rss2'));
    }

    // --- A2 readme: repointed off the random {{pick}} -----------------------------------------------

    public function test_a2_readme_renders_persona_version_not_the_old_pick(): void
    {
        $e = $this->engine($this->firstSeed([$this, 'servedExistingWp'], 'existing wordpress'));
        $v = $this->versionFromReadme($e);
        $b = $this->bodyOf($e, 'GET', '/readme.html');

        self::assertStringContainsString('Version ' . $v, $b);
        self::assertStringContainsString('WordPress &#8250; ReadMe', $b, 'the bundle witness survives');
        // None of the old hard-coded pick literals unless they happen to equal V.
        foreach (['6.4.2', '6.3.1', '5.9.3', '6.2.2'] as $old) {
            if ($old !== $v) {
                self::assertStringNotContainsString('Version ' . $old, $b, "the old {{pick}} literal {$old} is gone");
            }
        }
    }

    // --- A3 opml Content-Type + version -----------------------------------------------------------

    public function test_a3_opml_version_and_content_type(): void
    {
        $e = $this->engine($this->firstSeed([$this, 'servedExistingWp'], 'existing wordpress'));
        $v = $this->versionFromReadme($e);
        $resp = $e->respond(new RequestContext('GET', '/wp-links-opml.php'));

        self::assertNotNull($resp);
        self::assertStringContainsString('generator="WordPress/' . $v . '"', $resp->body);
        self::assertStringContainsString('text/xml', $resp->headers['Content-Type'] ?? '');
    }

    // --- A4 feed on BOTH seeds (unconditional) ----------------------------------------------------

    public function test_a4_feed_version_and_content_type_on_both_seeds(): void
    {
        foreach (['existing wordpress' => [$this, 'servedExistingWp'], 'route-wordpress' => [$this, 'servedRouteWp']] as $what => $pred) {
            $e = $this->engine($this->firstSeed($pred, $what));
            $v = $this->versionFromReadme($e);
            $resp = $e->respond(new RequestContext('GET', '/feed/'));

            self::assertNotNull($resp, "feed must serve on the {$what} seed");
            self::assertStringContainsString('https://wordpress.org/?v=' . $v, $resp->body, "feed discloses V on {$what}");
            self::assertStringNotContainsString('wordpress.orga', $resp->body, "attack tier took over the degenerate bundle on {$what}");
            self::assertStringContainsString('application/rss+xml', $resp->headers['Content-Type'] ?? '');
        }
    }

    // --- A5 rss2 on BOTH seeds + plain GET / not shadowed -----------------------------------------

    public function test_a5_rss2_serves_and_plain_root_is_not_shadowed(): void
    {
        foreach (['existing wordpress' => [$this, 'servedExistingWp'], 'route-wordpress' => [$this, 'servedRouteWp']] as $what => $pred) {
            $seed = $this->firstSeed($pred, $what);
            $e = $this->engine($seed);
            $v = $this->versionFromReadme($e);

            self::assertStringContainsString('https://wordpress.org/?v=' . $v, $this->bodyOf($e, 'GET', '/', 'feed=rss2'), "rss2 discloses V on {$what}");

            // A plain GET / must still serve the deploy homepage (the unconditional owns_path ['/'] rule
            // declines a query-less request) — never the RSS body, never a 404.
            $plain = $e->respond(new RequestContext('GET', '/'));
            self::assertNotNull($plain, "plain GET / must still serve on {$what}");
            self::assertStringNotContainsString('<rss', $plain->body, "plain GET / must not be shadowed by the rss2 rule on {$what}");
        }
    }

    // --- A6 install on BOTH seeds: version + preserved critical detection witnesses ----------------

    public function test_a6_install_version_and_detection_witnesses_on_both_seeds(): void
    {
        foreach (['existing wordpress' => [$this, 'servedExistingWp'], 'route-wordpress' => [$this, 'servedRouteWp']] as $what => $pred) {
            $e = $this->engine($this->firstSeed($pred, $what));
            $v = $this->versionFromReadme($e);
            $resp = $e->respond(new RequestContext('GET', '/wp-admin/install.php'));

            self::assertNotNull($resp, "install must serve on {$what}");
            self::assertStringContainsString('install.min.css?ver=' . $v, $resp->body, "install discloses V on {$what}");
            self::assertStringContainsString('<title>WordPress &rsaquo; Installation</title>', $resp->body, 'wp-install title witness preserved');
            self::assertStringContainsString('Site Title', $resp->body, 'wp-install Site Title witness preserved');
        }
    }

    // --- A7 homepage markers on the route-wordpress deploy -----------------------------------------

    public function test_a7_homepage_generator_and_emoji_on_route_wordpress(): void
    {
        $e = $this->engine($this->firstSeed([$this, 'servedRouteWp'], 'route-wordpress'));
        $v = $this->versionFromReadme($e);
        $home = $this->bodyOf($e, 'GET', '/');

        self::assertStringContainsString('<meta name="generator" content="WordPress ' . $v . '"', $home);
        self::assertStringContainsString('wp-emoji-release.min.js?ver=' . $v, $home);
    }

    // --- A8 non-WP `/` guard: no WP homepage marker, but rss2 still serves WP RSS (poly-stack) -----

    public function test_a8_non_wp_root_has_no_wp_marker_but_rss2_still_serves(): void
    {
        $seed = $this->firstSeed([$this, 'servedNonWp'], 'a non-WordPress persona');
        $e = $this->engine($seed);

        $home = $this->bodyOf($e, 'GET', '/');
        self::assertStringNotContainsString('<meta name="generator" content="WordPress', $home, 'no WP generator meta on a non-WP homepage');

        // Unconditional: /?feed=rss2 still serves WP RSS regardless of the served `/` persona.
        $rss2 = $e->respond(new RequestContext('GET', '/', 'feed=rss2'));
        self::assertNotNull($rss2, 'rss2 must serve even on a non-WP deploy (unconditional)');
        self::assertStringContainsString('https://wordpress.org/?v=', $rss2->body);
    }

    // --- A9 fingerprint-safety across every channel on both seeds ----------------------------------

    public function test_a9_all_channel_bodies_are_fingerprint_clean(): void
    {
        $guard = FingerprintGuard::fromPackage();
        foreach ([[$this, 'servedExistingWp'], [$this, 'servedRouteWp']] as $pred) {
            $e = $this->engine($this->firstSeed($pred, 'a WordPress persona'));
            $bodies = [
                $this->bodyOf($e, 'GET', '/'),
                $this->bodyOf($e, 'GET', '/readme.html'),
                $this->bodyOf($e, 'GET', '/wp-links-opml.php'),
                $this->bodyOf($e, 'GET', '/feed/'),
                $this->bodyOf($e, 'GET', '/wp-admin/install.php'),
                $this->bodyOf($e, 'GET', '/', 'feed=rss2'),
            ];
            foreach ($bodies as $body) {
                self::assertSame([], $guard->scan($body), 'channel body must be fingerprint-clean');
            }
        }
    }

    // --- A10 inert / no-500 / CT-match ------------------------------------------------------------

    public function test_a10_every_channel_is_200_with_its_declared_content_type(): void
    {
        $e = $this->engine($this->firstSeed([$this, 'servedRouteWp'], 'route-wordpress'));
        $cases = [
            ['GET', '/', '', 'text/html'],
            ['GET', '/readme.html', '', 'text/html'],
            ['GET', '/wp-links-opml.php', '', 'text/xml'],
            ['GET', '/feed/', '', 'application/rss+xml'],
            ['GET', '/wp-admin/install.php', '', 'text/html'],
            ['GET', '/', 'feed=rss2', 'application/rss+xml'],
        ];
        foreach ($cases as [$m, $p, $q, $ct]) {
            $resp = $e->respond(new RequestContext($m, $p, $q));
            self::assertNotNull($resp, "{$m} {$p}?{$q} must serve");
            self::assertSame(200, $resp->status, "{$m} {$p} status 200 (only-upgrade-404)");
            self::assertLessThan(500, $resp->status);
            self::assertStringContainsString($ct, $resp->headers['Content-Type'] ?? '', "{$m} {$p} Content-Type");
        }
    }

    // --- A11 compiled-artifact falsifier ----------------------------------------------------------

    public function test_a11_compiled_fold_added_route_wordpress_without_removing_existing(): void
    {
        $b = $this->index()['routes']['GET /']['b'] ?? [];
        $pids = array_map(static function (array $bundle): string {
            return (string) ($bundle['pid'] ?? '');
        }, $b);

        self::assertContains('route-wordpress', $pids, 'the new_page fold added route-wordpress at GET /');
        self::assertContains('wordpress', $pids, 'the existing degenerate wordpress variant was NOT removed');

        // The existing variant is still the dominant w=100 sig=1 fold.
        $existing = array_values(array_filter($b, static function (array $bundle): bool {
            return ($bundle['pid'] ?? null) === 'wordpress';
        }));
        self::assertNotEmpty($existing);
        self::assertSame(100, (int) ($existing[0]['w'] ?? 0), 'existing wordpress variant keeps w=100');

        $rules = require self::ATTACK;
        $ids = array_map(static function (array $r): string {
            return (string) ($r['id'] ?? '');
        }, $rules);
        foreach (['attack-wp-install', 'attack-wp-feed', 'attack-wp-feed-rss2'] as $need) {
            self::assertContains($need, $ids, "{$need} must compile into the attack index");
        }
    }
}
