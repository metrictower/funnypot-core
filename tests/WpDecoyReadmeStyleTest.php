<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\WordPress\VulnCatalog;
use PHPUnit\Framework\TestCase;

/**
 * FP-0393 — curated WordPress plugin/theme versioned readme/style decoy router.
 *
 * The three-tier serving reality the store presents for /wp-content/plugins/<slug>/readme.txt and
 * /wp-content/themes/<slug>/style.css:
 *   A — curated (catalog) slug   -> 200 with a real `Stable tag:`/`Version:` (the decoy this ticket adds)
 *   B — corpus long-tail slug    -> 200 generic (pre-existing detection bundle, untouched)
 *   C — absent slug              -> 404 (real store miss)
 *
 * Serving fixture is the committed compiled index (the file the engine reads); the tests pass only
 * after `composer build` regenerates + commits it.
 */
final class WpDecoyReadmeStyleTest extends TestCase
{
    private function seededInverter(string $seed): Honeypot
    {
        $store = new PhpArrayStore(require __DIR__ . '/../resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            'realistic'
        ));
    }

    /** Tier A, fresh keys: a curated plugin/theme with no pre-existing corpus key serves the versioned decoy. */
    public function test_tier_a_fresh_plugin_serves_versioned_readme(): void
    {
        $resp = $this->seededInverter('fixed')->respond(new RequestContext('GET', '/wp-content/plugins/tutor/readme.txt'));
        self::assertNotNull($resp, 'tutor readme.txt must serve a fake');
        self::assertSame(200, $resp->status, 'tutor readme status');
        self::assertSame('text/plain; charset=utf-8', $resp->headers['Content-Type'] ?? null, 'tutor readme Content-Type');
        // The exact WPScan/nuclei "found" witness: extracted version + slug literal.
        self::assertSame(1, preg_match('/(?mi)Stable tag:\s*3\.9\.4/', $resp->body), 'tutor must emit the catalog Stable tag');
        self::assertStringContainsString('tutor', $resp->body, 'tutor slug must appear literally in the body');
    }

    /** The corrected fusion-builder version (real CVE-2022-1386 max-vulnerable 3.6.1, not the ticket's illustrative 3.15.1). */
    public function test_tier_a_fresh_plugin_serves_primary_source_version(): void
    {
        $resp = $this->seededInverter('fixed')->respond(new RequestContext('GET', '/wp-content/plugins/fusion-builder/readme.txt'));
        self::assertNotNull($resp, 'fusion-builder readme.txt must serve a fake');
        self::assertSame(1, preg_match('/(?mi)Stable tag:\s*3\.6\.1/', $resp->body), 'fusion-builder must emit the verified max-vulnerable version');
    }

    /**
     * Tier A, colliding key: a curated slug that already has a generic corpus readme bundle must serve
     * the appended versioned bundle. Selection is seeded-weighted (w=1000 vs the corpus default), so the
     * seed is PINNED to one that lands on the versioned slice (not asserted to "always win").
     */
    public function test_tier_a_colliding_plugin_serves_versioned_readme(): void
    {
        $resp = $this->seededInverter('0')->respond(new RequestContext('GET', '/wp-content/plugins/contact-form-7/readme.txt'));
        self::assertNotNull($resp, 'contact-form-7 readme.txt must serve a fake');
        self::assertSame(200, $resp->status, 'contact-form-7 readme status');
        self::assertSame(1, preg_match('/(?mi)Stable tag:\s*5\.3\.1/', $resp->body), 'seed 0 must select the versioned bundle over the generic corpus bundle');
        self::assertStringContainsString('contact-form-7', $resp->body, 'contact-form-7 slug must appear literally');
    }

    /** Deterministic: the same seed serves a byte-identical body (catalog literal, non-flapping). */
    public function test_versioned_body_is_deterministic_for_a_seed(): void
    {
        $a = $this->seededInverter('7')->respond(new RequestContext('GET', '/wp-content/plugins/tutor/readme.txt'));
        $b = $this->seededInverter('7')->respond(new RequestContext('GET', '/wp-content/plugins/tutor/readme.txt'));
        self::assertNotNull($a);
        self::assertNotNull($b);
        self::assertSame($a->body, $b->body, 'the versioned body must be byte-identical across repeats for one seed');
    }

    /** Tier A theme: a curated theme serves style.css with `Version:` + `Theme Name:` (0 corpus theme keys → fresh). */
    public function test_tier_a_theme_serves_versioned_style_css(): void
    {
        $resp = $this->seededInverter('fixed')->respond(new RequestContext('GET', '/wp-content/themes/bricks/style.css'));
        self::assertNotNull($resp, 'bricks style.css must serve a fake');
        self::assertSame(200, $resp->status, 'bricks style status');
        self::assertSame('text/css; charset=utf-8', $resp->headers['Content-Type'] ?? null, 'bricks style Content-Type');
        self::assertSame(1, preg_match('/(?mi)Version:\s*1\.9\.6/', $resp->body), 'bricks must emit the catalog Version');
        self::assertStringContainsString('Theme Name:', $resp->body, 'bricks style.css must carry the theme header');
    }

    /** Tier B: the corpus long tail is untouched — a known corpus slug that is NOT curated still serves 200. */
    public function test_tier_b_corpus_long_tail_still_serves_200(): void
    {
        $resp = $this->seededInverter('fixed')->respond(new RequestContext('GET', '/wp-content/plugins/akismet/readme.txt'));
        self::assertNotNull($resp, 'akismet (tier B) must still serve a fake');
        self::assertSame(200, $resp->status, 'akismet must keep its pre-existing generic 200 (no assertion on a version — the corpus witness is mangled)');
    }

    /** Tier C: a slug absent from the store 404s. The chosen slug is re-grepped against the built index here. */
    public function test_tier_c_absent_slug_is_a_real_404(): void
    {
        $slug = 'zzz-funnypot-absent-slug';
        $index = (string) file_get_contents(__DIR__ . '/../resources/compiled/nuclei-index.full.php');
        self::assertStringNotContainsString($slug, $index, "tier-C test slug must be absent from the built index (a corpus refresh could add it — pick another)");

        $inv = $this->seededInverter('fixed');
        $resp = $inv->respond(new RequestContext('GET', '/wp-content/plugins/' . $slug . '/readme.txt'));
        self::assertNull($resp, 'an absent slug must not serve a bundle (falls through to a real 404)');
        self::assertFalse($inv->detect(new RequestContext('GET', '/wp-content/plugins/' . $slug . '/readme.txt'))->matched, 'an absent slug must not be detected');
    }

    /** Fingerprint-safety: no served decoy body carries a denylisted scanner-matcher token or a bare CRS rule id. */
    public function test_served_bodies_carry_no_fingerprint_token(): void
    {
        $denylist = require __DIR__ . '/../resources/fingerprint-denylist.php';
        $catalog = VulnCatalog::fromPackage();
        $inv = $this->seededInverter('0');

        $paths = [];
        foreach (array_keys($catalog->plugins()) as $slug) {
            $paths[] = '/wp-content/plugins/' . $slug . '/readme.txt';
        }
        foreach (array_keys($catalog->themes()) as $slug) {
            $paths[] = '/wp-content/themes/' . $slug . '/style.css';
        }

        foreach ($paths as $path) {
            $resp = $inv->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "{$path} must serve a fake");
            foreach ((array) $denylist['literals'] as $lit) {
                self::assertStringNotContainsStringIgnoringCase($lit, $resp->body, "{$path} must not carry denylisted literal '{$lit}'");
            }
            foreach ((array) $denylist['patterns'] as $re) {
                self::assertSame(0, preg_match('/' . $re . '/i', $resp->body), "{$path} must not match denylisted pattern '{$re}'");
            }
        }
    }

    /** Read API: has() is the curated-set membership test (a CVE-tag hint), NOT the serve gate (§6). */
    public function test_vuln_catalog_has_is_curated_membership_only(): void
    {
        $catalog = VulnCatalog::fromPackage();

        self::assertTrue($catalog->has('tutor'), 'a curated plugin is in the catalog');
        self::assertTrue($catalog->has('bricks'), 'a curated theme is in the catalog');
        // akismet serves 200 (tier B) but is NOT curated — proving has() is not the serve gate.
        self::assertFalse($catalog->has('akismet'), 'a tier-B corpus slug is not curated');
        self::assertFalse($catalog->has('zzz-funnypot-absent-slug'), 'an absent slug is not curated');

        $entry = $catalog->plugin('tutor');
        self::assertNotNull($entry);
        self::assertSame('3.9.4', $entry['version'], 'the catalog exposes the max-vulnerable version');
        self::assertSame('CVE-2026-0548', $entry['cve'], 'the catalog exposes the CVE for tagging');
    }
}
