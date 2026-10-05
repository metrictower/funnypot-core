<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\PersonaIdentity;
use PHPUnit\Framework\TestCase;

/**
 * FP-0428: Full Path Disclosure deception, end-to-end through Honeypot::respond().
 *
 * sqlmap provokes FPD to learn the absolute docroot before deploying a file stager: a direct
 * GET /wp-content/wp-db.php (WP core DB file requested standalone -> Uncaught Error), and array-parameter
 * pollution (id=1 -> id[]=1 -> a scalar builtin raises a PHP Warning). Both leak /var/www/<slug>/... which
 * sqlmap extracts and then targets. These are authored 200 bodies (never a real 500), rooted at the same
 * per-deploy docroot as the SQLi frame + phpinfo, with no attacker byte reflected.
 */
final class FpdDeceptionTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    private function body(?object $r): string
    {
        return $r !== null ? (string) $r->body : '';
    }

    public function test_wpdb_probes_leak_the_docroot_as_fatal_error(): void
    {
        foreach (['/wp-content/wp-db.php' => 'wp-content', '/wp-includes/wp-db.php' => 'wp-includes'] as $path => $sub) {
            $r = $this->resp($path);
            self::assertNotNull($r, "{$path} must serve");
            self::assertSame(200, $r->status, "{$path} must be 200 (never a real 500)");
            self::assertStringContainsString('text/html', (string) ($r->headers['Content-Type'] ?? ''), "{$path} Content-Type");
            $b = $this->body($r);
            self::assertStringContainsString('Call to undefined function', $b, "{$path} fatal wording");
            self::assertStringContainsString("/{$sub}/wp-db.php", $b, "{$path} must name the probed file");
            self::assertSame(1, preg_match('#<b>(/var/www/[a-z0-9]+/' . $sub . '/wp-db\.php)</b>#', $b), "{$path} extractable docroot");
        }
    }

    public function test_array_pollution_leaks_the_docroot_without_reflecting_the_param(): void
    {
        foreach (['/zzunrouted12345.php?zqxcustom[]=1', '/zzunrouted12345.php?zqxcustom%5B%5D=1'] as $path) {
            $r = $this->resp($path);
            self::assertNotNull($r, "{$path} must serve");
            self::assertSame(200, $r->status, "{$path} must be 200");
            self::assertStringContainsString('text/html', (string) ($r->headers['Content-Type'] ?? ''), "{$path} Content-Type");
            $b = $this->body($r);
            self::assertStringContainsString('array given', $b, "{$path} array-type warning");
            self::assertSame(1, preg_match('#<b>(/var/www/[a-z0-9]+/[^<>]+)</b> on line#', $b), "{$path} extractable docroot");
            // The attacker's param name is NEVER echoed (no reflector gate needed).
            self::assertStringNotContainsString('zqxcustom', $b, "{$path} must not reflect the param name");
        }
    }

    public function test_extracted_docroot_is_the_persona_docroot_not_a_real_host_path(): void
    {
        $slug = (string) PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial('fixed'))->field('company.slug');
        foreach (['/wp-content/wp-db.php', '/zzunrouted.php?a[]=1'] as $path) {
            $b = $this->body($this->resp($path));
            self::assertSame(1, preg_match('#/var/www/([a-z0-9]+)/#', $b, $m), "{$path} must name /var/www/<slug>/");
            self::assertSame($slug, $m[1], "{$path} docroot slug must be the persona slug (no real host path)");
        }
    }

    public function test_no_regression_store_hit_and_specific_exploit_win(): void
    {
        // A routed path is answered by the store FIRST — FPD must not shadow it.
        $index = $this->resp('/index.php?id[]=1');
        self::assertNotNull($index);
        self::assertStringNotContainsString('array given', $this->body($index), '/index.php must keep its store body, not FPD');

        // A compound payload (array form + a real injection) must get its SPECIFIC archetype, not FPD.
        $sqli = $this->body($this->resp("/zzunrouted.php?id[]=1' OR '1'='1"));
        self::assertStringContainsString('SQL syntax', $sqli, 'a compound sqli payload must get the sqli frame, not FPD');
        self::assertStringNotContainsString('array given', $sqli, 'the sqli archetype (priority < 90) must win over FPD');
    }

    public function test_sqlmap_regex_extracts_the_docroot(): void
    {
        // sqlmap's file-path extraction keys on a filesystem-path shape in the error output.
        foreach (['/wp-content/wp-db.php', '/zzunrouted.php?p[]=1'] as $path) {
            $b = $this->body($this->resp($path));
            self::assertSame(1, preg_match('#(/var/www/[a-z0-9]+(?:/[\w.-]+)+\.php)#', $b, $m), "{$path} sqlmap path-shape extraction");
            self::assertStringStartsWith('/var/www/', $m[1]);
        }
    }
}
