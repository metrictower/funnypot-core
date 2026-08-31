<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\SiteProfile;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Template\TemplateAttackEmulator;
use Funnypot\Core\Verdict;
use PHPUnit\Framework\TestCase;

/**
 * The top 404 gaps a ZAP scan of this honeypot found: the bare IMDSv1 metadata-category
 * listing (attack/91-imds-base.yaml), phpMyAdmin's own theme stylesheet (route/241), the
 * unauthenticated /wp-admin redirect our own wp-login.php page dangles a link to
 * (attack/104-wp-admin-redirect.yaml), and an exposed .aws directory plus the two files its
 * own listing links (route/234-236). Each closes a real 404 without opening a new dead-link
 * or incoherent-content tell.
 */
final class ZapCoverageTest extends TestCase
{
    private const ATTACK_COMPILED = __DIR__ . '/../resources/compiled/funnypot-attack.php';

    private function emulator(): TemplateAttackEmulator
    {
        return TemplateAttackEmulator::fromFile(self::ATTACK_COMPILED);
    }

    /** A full Honeypot over the REAL compiled corpus (what PhpArrayStore::fromPackage() loads in prod). */
    private function fullEngine(string $seed = 'fixed', bool $attackEmulation = true): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');
        $config = new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic',
            'high',
            65536,
            0,
            0,
            $attackEmulation
        );

        return new Honeypot($store, $config);
    }

    // --- Compiled-artifact guards -------------------------------------------------------------

    public function test_attack_rule_count_is_59_plus_the_two_new_rules(): void
    {
        $rules = require self::ATTACK_COMPILED;
        self::assertCount(65, $rules, 'attack rule count must be 59 (baseline) + 2 (imds-base, wp-admin-redirect) + 2 (lfi-sshkey, lfi-hostname) + 1 (imds-identity-doc) + 1 (FP-0229 nextjs-rsc)');

        $ids = array_map(static function (array $r): string { return (string) $r['id']; }, $rules);
        self::assertContains('attack-imds-base', $ids);
        self::assertContains('attack-imds-identity-doc', $ids, 'the coherent instance-identity document rule');
        self::assertContains('attack-wp-admin-redirect', $ids);
        // Target-aware LFI: an id_rsa/.ssh or /etc/hostname read returns key/hostname content
        // instead of a format-mismatched passwd, each ahead of the generic passwd rule.
        self::assertContains('attack-lfi-sshkey', $ids);
        self::assertContains('attack-lfi-hostname', $ids);
        // The pre-existing AI/CRS families must stay intact — this integration touches neither.
        self::assertContains('attack-cloud-imds', $ids, 'the deeper 90-imds rule must be untouched');
        self::assertContains('attack-wp-login', $ids, 'the wp-login credential oracle must be untouched');
    }

    public function test_route_rule_count_is_128_plus_the_new_rules(): void
    {
        $rules = require __DIR__ . '/../resources/compiled/funnypot-routes.php';
        self::assertCount(164, $rules, 'route rule count must be 128 (baseline) + 4 (css, listing, credentials, config) + 6 (.env family: development/staging/test/bak/php/laravel-subdir) + 12 (VCS-exposure pack: 3 enrich .git-logs/.bzr/.hg-hgrc + 9 new .git/.svn/.hg pages) + 3 (CVS/Entries + TYPO3 typo3conf listing + localconf.php) + 10 (WordPress REST wp/v2: users/posts/pages/comments/media/categories/tags/types/statuses/settings) + 1 (FP-0229 nextjs app-shell)');

        $ids = array_map(static function (array $r): string { return (string) $r['id']; }, $rules);
        self::assertContains('route-phpmyadmin-css', $ids);
        self::assertContains('route-dotaws-listing', $ids);
        self::assertContains('route-aws-cli-credentials', $ids);
        self::assertContains('route-aws-cli-config', $ids);
        // .env suffix family + .env.php source leak + subdir install.
        self::assertContains('route-envfile-dev', $ids);
        self::assertContains('route-envfile-staging', $ids);
        self::assertContains('route-envfile-test', $ids);
        self::assertContains('route-envfile-bak', $ids);
        self::assertContains('route-envfile-php-src', $ids);
        self::assertContains('route-envfile-laravel', $ids);
        // VCS-exposure pack: 3 enrich rules (dress corpus git-logs / bzr / hg-hgrc bundles) + 9
        // brand-new .git/.svn/.hg pages. The new-page ids are route-vcs-* (never carrying `git`), so
        // route-git-config's broad `git` needle cannot hijack them.
        self::assertContains('route-git-logs-head', $ids);
        self::assertContains('route-bzr-branch-conf', $ids);
        self::assertContains('route-hg-hgrc', $ids);
        self::assertContains('route-vcs-head', $ids);
        self::assertContains('route-vcs-packed-refs', $ids);
        self::assertContains('route-vcs-refs-main', $ids);
        self::assertContains('route-vcs-description', $ids);
        self::assertContains('route-vcs-commit-msg', $ids);
        self::assertContains('route-vcs-exclude', $ids);
        self::assertContains('route-vcs-info-refs', $ids);
        self::assertContains('route-vcs-svn-entries', $ids);
        self::assertContains('route-vcs-hg-requires', $ids);
        // CVS/Entries (third VCS-metadata exposure) + the TYPO3 typo3conf listing/localconf pair.
        self::assertContains('route-vcs-cvs-entries', $ids);
        self::assertContains('route-typo3conf-listing', $ids);
        self::assertContains('route-typo3conf-localconf', $ids);
        // WordPress REST API wp/v2 collection bodies (one per endpoint).
        self::assertContains('route-wp-json-v2-users', $ids);
        self::assertContains('route-wp-json-v2-posts', $ids);
        self::assertContains('route-wp-json-v2-pages', $ids);
        self::assertContains('route-wp-json-v2-comments', $ids);
        self::assertContains('route-wp-json-v2-media', $ids);
        self::assertContains('route-wp-json-v2-categories', $ids);
        self::assertContains('route-wp-json-v2-tags', $ids);
        self::assertContains('route-wp-json-v2-types', $ids);
        self::assertContains('route-wp-json-v2-statuses', $ids);
        self::assertContains('route-wp-json-v2-settings', $ids);
    }

    // --- IMDS base listing (attack/91-imds-base.yaml) -----------------------------------------

    public function test_imds_base_lists_categories_as_plain_text(): void
    {
        foreach (['/latest/meta-data', '/latest/meta-data/'] as $path) {
            $r = $this->emulator()->emulate(new RequestContext('GET', $path));
            self::assertNotNull($r, $path);
            self::assertSame(200, $r->status, $path);
            self::assertSame('text/plain', $r->headers['Content-Type'], $path);
            self::assertStringContainsString('ami-id', $r->body, $path);
            self::assertStringContainsString('instance-id', $r->body, $path);
        }
    }

    public function test_imds_base_is_disjoint_from_the_deeper_credentials_rule(): void
    {
        // 90-imds.yaml owns the deeper credential/identity sub-paths; 91-imds-base must not
        // shadow it (and must not itself fire on those deeper paths).
        $r = $this->emulator()->emulate(new RequestContext('GET', '/latest/meta-data/iam/security-credentials/my-role'));
        self::assertNotNull($r);
        self::assertSame(['attack-cloud-imds'], $r->satisfies->templateIds());
        self::assertStringContainsString('AccessKeyId', $r->body);
    }

    // --- phpMyAdmin theme stylesheet (route/241-phpmyadmin-css.yaml) ---------------------------

    /** @return array<string,array{0:string}> */
    public static function phpmyadminCssPaths(): array
    {
        return [
            'phpmyadmin/'  => ['/phpmyadmin/phpmyadmin.css.php'],
            'phpMyAdmin/'  => ['/phpMyAdmin/phpmyadmin.css.php'],
            'pma/'         => ['/pma/phpmyadmin.css.php'],
            'bare root'    => ['/phpmyadmin.css.php'],
        ];
    }

    /** @dataProvider phpmyadminCssPaths */
    public function test_phpmyadmin_css_serves_the_theme_stylesheet(string $path): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('GET', $path));
        self::assertNotNull($r, $path);
        self::assertSame(200, $r->status, $path);
        self::assertSame('text/css; charset=UTF-8', $r->headers['Content-Type'] ?? null, $path);
        self::assertStringContainsString('loginform', $r->body, $path);
        self::assertStringContainsString('pma-card', $r->body, $path);
        // Hand-written, not a vendored release: no version pin.
        self::assertDoesNotMatchRegularExpression('/\d+\.\d+\.\d+/', $r->body, $path);
    }

    public function test_phpmyadmin_css_never_collides_with_the_mock_auth_gate(): void
    {
        // The gate (attack/102) owns the panel roots, not the .css.php asset path — a GET to the
        // stylesheet must still be the css.php body, never the login page/gate.
        $r = $this->fullEngine()->respond(new RequestContext('GET', '/phpmyadmin/phpmyadmin.css.php'));
        self::assertNotNull($r);
        self::assertStringNotContainsString('pma_username', $r->body);
        self::assertStringNotContainsString('<html', $r->body);
    }

    // --- wp-admin unauthenticated redirect (attack/104-wp-admin-redirect.yaml) ------------------

    private const WP_ADMIN_LOCATION = '/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1';

    /** @return array<string,array{0:string,1:string}> */
    public static function wpAdminVariants(): array
    {
        return [
            'bare'                 => ['GET', '/wp-admin'],
            'trailing slash'       => ['GET', '/wp-admin/'],
            'double trailing slash' => ['GET', '/wp-admin//'],
            'triple trailing slash' => ['GET', '/wp-admin///'],
            'mixed case'           => ['GET', '/WP-Admin'],
            'upper case'           => ['GET', '/WP-ADMIN/'],
            'HEAD bare'            => ['HEAD', '/wp-admin'],
            'HEAD trailing slash'  => ['HEAD', '/wp-admin/'],
            'HEAD double slash'    => ['HEAD', '/wp-admin//'],
        ];
    }

    /** @dataProvider wpAdminVariants */
    public function test_wp_admin_variants_redirect_to_wp_login_never_a_404_or_dashboard(string $method, string $path): void
    {
        $r = $this->emulator()->emulate(new RequestContext($method, $path));
        self::assertNotNull($r, "{$method} {$path}");
        self::assertSame(302, $r->status, "{$method} {$path}");
        self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location'], "{$method} {$path}");
        self::assertSame('', $r->body, "{$method} {$path}: a redirect must carry no body");
    }

    public function test_wp_admin_owns_the_path_so_classify_sees_the_override(): void
    {
        self::assertTrue($this->emulator()->ownsPath('/wp-admin'));
        self::assertTrue($this->emulator()->ownsPath('/wp-admin/'));
        self::assertTrue($this->emulator()->ownsPath('/WP-ADMIN//'));
    }

    public function test_wp_admin_served_end_to_end_over_the_real_corpus(): void
    {
        $engine = $this->fullEngine();
        foreach (['/wp-admin', '/wp-admin/'] as $path) {
            $v = $engine->classify(new RequestContext('GET', $path), SiteProfile::empty());
            self::assertSame(Verdict::ATTACK_CLASS, $v->classification, $path);
            self::assertSame('attack-wp-admin-redirect', $v->fakeHandle->ruleId, $path);

            $r = $engine->respond(new RequestContext('GET', $path));
            self::assertNotNull($r, $path);
            self::assertSame(302, $r->status, $path);
            self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location'], $path);
        }
    }

    public function test_wp_admin_location_is_a_static_literal_a_crafted_query_cannot_change(): void
    {
        // Bodies with an unrelated attack-class shape (e.g. an LFI/SQLi payload) are deliberately
        // excluded here: those collide with OTHER broad, path-agnostic attack rules ahead of this
        // one in priority (pre-existing precedence, not this rule's concern) — this test only pins
        // that THIS rule never reflects a query value into its own Location.
        $cases = [
            '',
            'redirect_to=https%3A%2F%2Fevil.example%2F',
            'redirect_to=' . rawurlencode('https://evil.example/'),
            'reauth=0&redirect_to=%2Fwp-admin%2Fother%2F',
        ];
        foreach ($cases as $query) {
            $r = $this->fullEngine()->respond(new RequestContext('GET', '/wp-admin', $query));
            self::assertNotNull($r, $query);
            self::assertSame(self::WP_ADMIN_LOCATION, $r->headers['Location'], "query={$query}");
            self::assertStringNotContainsString('evil.example', $r->headers['Location'], "query={$query}");
        }
    }

    /**
     * Variant-decline safety: a method this rule never matches (POST/PUT/TRACE/OPTIONS/DELETE)
     * must never surface a 302, a Location, or a 200 authed/dashboard body — it must fall through
     * to CLEAN (the app's own 404), since there is no other bundle at this path.
     *
     * @dataProvider declinedMethodProvider
     */
    public function test_non_get_head_methods_never_get_the_redirect_or_a_dashboard(string $method): void
    {
        $engine = $this->fullEngine();
        $r = $engine->respond(new RequestContext($method, '/wp-admin'));
        if ($r === null) {
            self::assertNull($r); // CLEAN / gate-declined: the safe outcome.

            return;
        }
        self::assertNotSame(302, $r->status, $method);
        self::assertArrayNotHasKey('Location', $r->headers, $method);
        self::assertStringNotContainsString('wp-admin', strtolower($r->body), $method);
    }

    /** @return array<string,array{0:string}> */
    public function declinedMethodProvider(): array
    {
        return [
            'POST'    => ['POST'],
            'PUT'     => ['PUT'],
            'DELETE'  => ['DELETE'],
            'TRACE'   => ['TRACE'],
            'OPTIONS' => ['OPTIONS'],
        ];
    }

    // --- Exposed .aws directory + its two linked files (route/234-236) -------------------------

    public function test_dotaws_listing_serves_an_autoindex_naming_both_files(): void
    {
        foreach (['/.aws', '/.aws/'] as $path) {
            $r = $this->fullEngine()->respond(new RequestContext('GET', $path));
            self::assertNotNull($r, $path);
            self::assertSame(200, $r->status, $path);
            self::assertSame('text/html; charset=utf-8', $r->headers['Content-Type'] ?? null, $path);
            self::assertStringContainsString('Index of /.aws', $r->body, $path);
            self::assertStringContainsString('href="credentials"', $r->body, $path);
            self::assertStringContainsString('href="config"', $r->body, $path);
            // Version-less, and no fixed/localhost host baked in.
            self::assertDoesNotMatchRegularExpression('/Apache\/[\d.]+/', $r->body, $path);
            self::assertStringNotContainsString('localhost', $r->body, $path);
        }
    }

    public function test_dotaws_listing_links_both_resolve_no_dead_link_tell(): void
    {
        // The whole point of wiring 235/236 alongside the listing: neither linked file may 404.
        $engine = $this->fullEngine();
        foreach (['/.aws/credentials', '/.aws/config'] as $path) {
            $r = $engine->respond(new RequestContext('GET', $path));
            self::assertNotNull($r, "{$path} must serve a fake, not dangle as a dead link off the listing");
            self::assertSame(200, $r->status, $path);
        }
    }

    public function test_dotaws_credentials_serves_inert_ini_creds(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('GET', '/.aws/credentials'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/plain; charset=utf-8', $r->headers['Content-Type'] ?? null);
        self::assertStringContainsString('[default]', $r->body);
        self::assertSame(1, preg_match('/aws_access_key_id = (AKIA[A-Z2-7]{16})/', $r->body, $m));
        self::assertSame(1, preg_match('/aws_secret_access_key = (\S+)/', $r->body));
    }

    public function test_dotaws_config_serves_region_and_output(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('GET', '/.aws/config'));
        self::assertNotNull($r);
        self::assertSame(200, $r->status);
        self::assertSame('text/plain; charset=utf-8', $r->headers['Content-Type'] ?? null);
        self::assertStringContainsString('[default]', $r->body);
        self::assertSame(1, preg_match('/region = (\S+)/', $r->body));
        self::assertStringContainsString('output = json', $r->body);
    }

    public function test_dotaws_credentials_and_config_agree_with_credentials_txt_on_one_identity(): void
    {
        // One host, one identity: the .aws/credentials + .aws/config pair must render the SAME
        // persona AWS access key / secret / region as the legacy /credentials.txt surface — not
        // a second, contradicting AWS account.
        $engine = $this->fullEngine();
        $creds = $engine->respond(new RequestContext('GET', '/.aws/credentials'));
        $conf = $engine->respond(new RequestContext('GET', '/.aws/config'));
        $legacy = $engine->respond(new RequestContext('GET', '/credentials.txt'));
        self::assertNotNull($creds);
        self::assertNotNull($conf);
        self::assertNotNull($legacy);

        self::assertSame(1, preg_match('/aws_access_key_id = (AKIA[A-Z2-7]{16})/', $creds->body, $ak));
        self::assertSame(1, preg_match('/AWS_ACCESS_KEY_ID=(AKIA[A-Z2-7]{16})/', $legacy->body, $al));
        self::assertSame($al[1], $ak[1], 'the AWS access key id must be identical across .aws/credentials and credentials.txt');

        self::assertSame(1, preg_match('/aws_secret_access_key = (\S+)/', $creds->body, $sk));
        self::assertSame(1, preg_match('/AWS_SECRET_ACCESS_KEY=(\S+)/', $legacy->body, $sl));
        self::assertSame($sl[1], $sk[1], 'the AWS secret access key must be identical across .aws/credentials and credentials.txt');

        self::assertSame(1, preg_match('/region = (\S+)/', $conf->body, $rk));
        self::assertSame(1, preg_match('/AWS_DEFAULT_REGION=(\S+)/', $legacy->body, $rl));
        self::assertSame($rl[1], $rk[1], 'the AWS region must be identical across .aws/config and credentials.txt');
    }

    // --- Fingerprint safety on the served bodies (not only the compiled artifacts) -------------

    public function test_new_surfaces_carry_no_denied_fingerprint_token(): void
    {
        $guard = FingerprintGuard::fromPackage();
        $engine = $this->fullEngine();
        $emulator = $this->emulator();

        $routePaths = [
            '/.aws', '/.aws/', '/.aws/credentials', '/.aws/config',
            '/phpmyadmin/phpmyadmin.css.php', '/phpMyAdmin/phpmyadmin.css.php',
            '/pma/phpmyadmin.css.php', '/phpmyadmin.css.php',
        ];
        for ($seed = 0; $seed <= 20; $seed++) {
            $inv = new Honeypot(
                new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php'),
                new Config(
                    'respond',
                    static function (RequestContext $r): bool { return true; },
                    'matched-only',
                    static function (RequestContext $r) use ($seed): string { return (string) $seed; },
                    'coherent',
                    'realistic'
                )
            );
            foreach ($routePaths as $path) {
                $r = $inv->respond(new RequestContext('GET', $path));
                self::assertNotNull($r, "{$path} seed {$seed} must serve a fake");
                self::assertSame([], $guard->scan($r->body), "{$path} seed {$seed} leaks a denied fingerprint token: " . $r->body);
            }
        }

        // The attack-tier rules render via renderRule() directly (no store seed needed).
        $r91 = $emulator->emulate(new RequestContext('GET', '/latest/meta-data/'));
        self::assertNotNull($r91);
        self::assertSame([], $guard->scan($r91->body));

        $r104 = $emulator->emulate(new RequestContext('GET', '/wp-admin/'));
        self::assertNotNull($r104);
        self::assertSame([], $guard->scan($r104->body));
    }

    // --- Deferred: route/386-trace-axd.yaml is intentionally NOT integrated --------------------
    // An ASP.NET/IIS trace.axd disclosure is persona-incoherent on this PHP/WordPress/Apache
    // honeypot (a tell, not a fix) — left as a draft pending a Windows/IIS persona decision.
    public function test_trace_axd_is_not_wired_up(): void
    {
        $r = $this->fullEngine()->respond(new RequestContext('GET', '/trace.axd'));
        self::assertNull($r, '/trace.axd must stay unwired — deferred pending an IIS persona decision');
    }
}
