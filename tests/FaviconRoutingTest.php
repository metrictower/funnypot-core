<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Store\PhpArrayStore;
use Funnypot\Core\Support\FaviconHash;
use PHPUnit\Framework\TestCase;

/**
 * FP-0230 — the persona-coherent favicons serve byte-identically and hash to their product signature,
 * end-to-end through the real compiled index, under BOTH response styles.
 *
 * Test C proves the base64-at-rest bin path (compiler + emulator + the A5 bin-bypass) returns the exact
 * committed bytes with an image content-type and no charset — so a scanner following a decoy page's
 * <link rel="icon"> gets a hash-matching icon. Test D proves the bare-root /favicon.ico serves a neutral
 * icon (never a known-product signature) and that every wired <link rel="icon"> points at a path this
 * pack actually serves (no dangling favicon link).
 */
final class FaviconRoutingTest extends TestCase
{
    private const REPO = __DIR__ . '/..';

    /** product => [favicon path, signed-int32 signature, asset basename] */
    private const FORGED = [
        'grafana'    => ['/grafana/favicon.ico',    999357577,   'grafana'],
        'phpmyadmin' => ['/phpmyadmin/favicon.ico', -1588080585, 'phpmyadmin'],
        'jenkins'    => ['/jenkins/favicon.ico',    81586312,    'jenkins'],
        'tomcat'     => ['/manager/favicon.ico',    116323821,   'tomcat'],
    ];

    /** Published product signatures — a neutral favicon must match none of these. */
    private const KNOWN_SIGNATURES = [
        81586312, -335242539, 999357577, -1588080585, 988422585, 116323821,
        1485257654, -297069493, -1395229095, 1354567968, -962726853,
    ];

    private function inverter(string $style): Honeypot
    {
        $store = new PhpArrayStore(require self::REPO . '/resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r): string { return 'fixed'; },
            'coherent',
            $style
        ));
    }

    private function seededInverter(string $seed, string $style): Honeypot
    {
        $store = new PhpArrayStore(require self::REPO . '/resources/compiled/nuclei-index.full.php');

        return new Honeypot($store, new Config(
            'respond',
            static function (RequestContext $r): bool { return true; },
            'matched-only',
            static function (RequestContext $r) use ($seed): string { return $seed; },
            'coherent',
            $style
        ));
    }

    /**
     * @dataProvider forgedFavicons
     */
    public function test_favicon_serves_exact_bytes_and_matching_hash_under_both_styles(string $product, string $path, int $signature, string $asset): void
    {
        $expected = file_get_contents(self::REPO . '/resources/favicons/' . $asset . '.ico');
        self::assertNotFalse($expected, "asset {$asset}.ico must exist");

        foreach (['minimal', 'realistic'] as $style) {
            $resp = $this->inverter($style)->respond(new RequestContext('GET', $path));
            self::assertNotNull($resp, "[{$style}] {$path} must serve a favicon (bin bypasses minimal-synth)");
            self::assertSame(200, $resp->status, "[{$style}] {$path} status");
            // Byte-identical to the committed asset — no directive render, taunt, or token mutation.
            self::assertSame($expected, $resp->body, "[{$style}] {$path} must serve byte-identical bytes");
            // An image content-type with NO charset (a charset on an icon is a tell; also invariant #5).
            $ct = $resp->headers['Content-Type'] ?? null;
            self::assertSame('image/x-icon', $ct, "[{$style}] {$path} Content-Type must be image/x-icon, no charset");
            // The whole point: the served bytes hash to the product's published signature.
            self::assertSame($signature, FaviconHash::hash($resp->body), "[{$style}] {$path} must hash to {$product}'s signature");
            // Size-capped (AC): a favicon is small.
            self::assertLessThan(10240, strlen($resp->body), "[{$style}] {$path} must be under the 10KB favicon cap");
        }
    }

    /** @return array<string,array{0:string,1:string,2:int,3:string}> */
    public static function forgedFavicons(): array
    {
        $out = [];
        foreach (self::FORGED as $product => [$path, $sig, $asset]) {
            $out[$product] = [$product, $path, $sig, $asset];
        }

        return $out;
    }

    public function test_committed_assets_hash_to_declared_signatures(): void
    {
        // A4 per-asset gate (regression guard if an asset is edited): each committed favicon file
        // hashes to its declared signature. NOT a proof of mmh3-equivalence (it shares FaviconHash
        // with the forge) — FaviconHashTest's independent oracle carries that; this pins the assets.
        foreach (self::FORGED as $product => [, $sig, $asset]) {
            $bytes = file_get_contents(self::REPO . '/resources/favicons/' . $asset . '.ico');
            self::assertSame($sig, FaviconHash::hash($bytes), "committed {$asset}.ico must hash to {$product}'s signature");
            // A valid ICO (magic 00 00 01 00) and license-clean self-generated blob (not vendored).
            self::assertSame("\x00\x00\x01\x00", substr($bytes, 0, 4), "{$asset}.ico must be a valid ICO");
        }
    }

    public function test_bare_root_favicon_is_neutral_never_a_product_signature(): void
    {
        // AC#4: bare /favicon.ico serves a neutral icon (contradicts nothing) — never a known-product
        // hash (which would be the deferred cross-path incoherence). Sweep seeds; whenever the neutral
        // image bundle wins the polluted key, assert it is a valid ICO and its hash is not in the table.
        $servedNeutral = 0;
        for ($seed = 0; $seed <= 80; $seed++) {
            $resp = $this->seededInverter((string) $seed, 'realistic')->respond(new RequestContext('GET', '/favicon.ico'));
            if ($resp === null) {
                continue;
            }
            if (substr($resp->body, 0, 4) === "\x00\x00\x01\x00") {
                $servedNeutral++;
                self::assertNotContains(
                    FaviconHash::hash($resp->body),
                    self::KNOWN_SIGNATURES,
                    "seed {$seed}: the bare-root favicon must not hash to any known product signature"
                );
                self::assertSame('image/x-icon', $resp->headers['Content-Type'] ?? null, "seed {$seed}: neutral favicon Content-Type");
            }
        }
        // The weighted neutral bundle must actually win the polluted key for a meaningful share of seeds.
        self::assertGreaterThan(10, $servedNeutral, 'the neutral favicon must serve for a meaningful share of seeds');
    }

    public function test_neutral_asset_is_not_a_known_signature(): void
    {
        $neutral = file_get_contents(self::REPO . '/resources/favicons/neutral.ico');
        self::assertNotContains(FaviconHash::hash($neutral), self::KNOWN_SIGNATURES, 'the neutral asset must not collide with a known product signature');
    }

    public function test_decoy_pages_link_only_to_served_favicon_paths(): void
    {
        // Within-page coherence wiring: each decoy page's <link rel="icon" href="X"> must point at a
        // favicon path this pack actually serves (Shodan follows the link). A dangling favicon link
        // (404) would be its own tell. Assert both the link presence AND that the target serves the
        // matching-hash icon.
        $inv = $this->inverter('realistic');

        // The fixed-path new_page decoys (grafana, phpmyadmin) serve at a known key: assert the page
        // itself carries the <link rel="icon"> pointing at its favicon path.
        $pageLinks = [
            '/grafana/'    => '/grafana/favicon.ico',
            '/phpmyadmin/' => '/phpmyadmin/favicon.ico',
        ];
        foreach ($pageLinks as $page => $faviconPath) {
            $pageResp = $inv->respond(new RequestContext('GET', $page));
            self::assertNotNull($pageResp, "{$page} must serve");
            self::assertStringContainsString(
                'href="' . $faviconPath . '"',
                $pageResp->body,
                "{$page} must link its favicon {$faviconPath}"
            );
        }

        // Every wired favicon path (incl. the needle-enrich tomcat/jenkins pages, whose page URL is
        // corpus-routed but whose <link> is an absolute path) serves the matching-hash icon — no
        // dangling favicon link.
        foreach (self::FORGED as $product => [$faviconPath, $sig]) {
            $fav = $inv->respond(new RequestContext('GET', $faviconPath));
            self::assertNotNull($fav, "{$faviconPath} must serve");
            self::assertSame($sig, FaviconHash::hash($fav->body), "{$faviconPath} must serve {$product}'s matching-hash icon");
        }
    }
}
