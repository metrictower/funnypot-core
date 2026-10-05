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
 * FP-0410: PAN-OS GlobalProtect ETag build-timestamp version oracle. /global-protect/login.esp is enriched
 * into a believable portal; the four static assets (login.css, Pan.js, favicon.ico, bg.png) each carry an
 * ETag whose 8-hex value is the firmware build epoch and a matching Last-Modified, all from the persona
 * panos.* triple — panos-scanner / Wapiti decode the ETag's epoch to the PAN-OS version. ETag/Last-Modified/
 * version all derive from one PANOS_BUILDS index (coherent, deploy-stable). Self-generated ICO/PNG (no real
 * PAN-OS bytes). Fixture: full compiled corpus via Honeypot::respond(). (The engine normalizes the header
 * name to `Etag`, which is HTTP-case-insensitive and what a scanner reads.)
 */
final class PanosEtagOracleTest extends TestCase
{
    private const ASSETS = [
        '/global-protect/portal/css/login.css' => 'text/css',
        '/js/Pan.js' => 'application/javascript',
        '/global-protect/portal/images/favicon.ico' => 'image/x-icon',
        '/global-protect/portal/images/bg.png' => 'image/png',
    ];

    /** @var array<string,mixed>|null */
    private static $idx;

    /** @var array<string,Honeypot> per-seed engine cache (heap-churn lesson). */
    private static $engines = [];

    private function engine(string $seed = 'fixed'): Honeypot
    {
        if (isset(self::$engines[$seed])) {
            return self::$engines[$seed];
        }
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static function (RequestContext $r): bool { return true; }, 'matched-only',
            static function (RequestContext $r): string { return 'fixed'; }, 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, $seed);
        $cfg->attackEmulation = true;

        return self::$engines[$seed] = new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function resp(string $path, string $seed = 'fixed'): ?object
    {
        return $this->engine($seed)->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
    }

    /** @param array<string,string> $headers */
    private function header(array $headers, string $name): ?string
    {
        foreach ($headers as $k => $v) {
            if (strcasecmp((string) $k, $name) === 0) {
                return (string) $v;
            }
        }

        return null;
    }

    public function test_login_esp_serves_portal_every_seed(): void
    {
        for ($s = 0; $s < 24; $s++) {
            $b = $s === 0 ? $this->body0() : (string) ($this->resp('/global-protect/login.esp', (string) $s)->body ?? '');
            self::assertStringContainsString('GlobalProtect Portal', $b, "seed {$s} must serve the portal (either bundle pick)");
        }
    }

    private function body0(): string
    {
        return (string) ($this->resp('/global-protect/login.esp', '0')->body ?? '');
    }

    public function test_assets_serve_etag_lastmodified_and_content_type(): void
    {
        foreach (self::ASSETS as $path => $ct) {
            $r = $this->resp($path);
            self::assertSame(200, $r->status ?? null, "{$path} must serve 200");
            $h = (array) ($r->headers ?? []);
            self::assertStringContainsString($ct, (string) $this->header($h, 'Content-Type'), "{$path} Content-Type");
            $etag = $this->header($h, 'ETag');
            self::assertNotNull($etag, "{$path} must carry an ETag");
            self::assertSame(1, preg_match('/^"[0-9a-f]{8}"$/', (string) $etag), "{$path} ETag must be a quoted 8-hex epoch: {$etag}");
            self::assertNotNull($this->header($h, 'Last-Modified'), "{$path} must carry Last-Modified");
        }
    }

    public function test_etag_decodes_to_the_persona_version_build_date(): void
    {
        $seed = 'hostZ';
        $ps = PersonaIdentity::fromSeed(PersonaIdentity::seedFromMaterial($seed));
        $expectEtag = $ps->field('panos.etag');
        foreach (array_keys(self::ASSETS) as $path) {
            $h = (array) ($this->resp($path, $seed)->headers ?? []);
            self::assertSame('"' . $expectEtag . '"', $this->header($h, 'ETag'), "{$path} ETag must be the persona panos.etag");
            // The ETag hex epoch and Last-Modified must decode to the SAME UTC date (the version's build date).
            $etagDate = gmdate('Y-m-d', hexdec((string) $expectEtag));
            $lmDate = gmdate('Y-m-d', (int) strtotime((string) $this->header($h, 'Last-Modified')));
            self::assertSame($etagDate, $lmDate, "{$path} ETag epoch and Last-Modified must agree");
        }
    }

    public function test_triple_is_coherent_and_deploy_stable(): void
    {
        // All four assets share one ETag/Last-Modified per deploy (one build index).
        $etags = [];
        foreach (array_keys(self::ASSETS) as $path) {
            $etags[] = $this->header((array) ($this->resp($path, 'depA')->headers ?? []), 'ETag');
        }
        self::assertCount(1, array_unique($etags), 'all four assets must share one ETag per deploy');
        // Deploy-stable + varies across deploys.
        self::assertSame($this->header((array) ($this->resp('/js/Pan.js', 'depA')->headers ?? []), 'ETag'),
            $this->header((array) ($this->resp('/js/Pan.js', 'depA')->headers ?? []), 'ETag'), 'stable per deploy');
    }

    public function test_fingerprint_safe_across_builds(): void
    {
        // Every PANOS_BUILDS entry must render fingerprint-safe values (etag/version/last-modified).
        for ($s = 0; $s < 400; $s++) {
            $ps = PersonaIdentity::fromSeed($s);
            $blob = $ps->field('panos.version') . ' ' . $ps->field('panos.etag') . ' ' . $ps->field('panos.lastModified');
            self::assertSame(0, preg_match('/\b9\d{5}\b/', $blob), "seed {$s} panos triple denylist run: {$blob}");
            self::assertSame(1, preg_match('/^[0-9a-f]{8}$/', (string) $ps->field('panos.etag')), "seed {$s} etag must be 8-hex");
        }
    }

    public function test_binary_assets_are_self_generated_valid_images(): void
    {
        $ico = (string) ($this->resp('/global-protect/portal/images/favicon.ico')->body ?? '');
        self::assertSame("\x00\x00\x01\x00", substr($ico, 0, 4), 'favicon must be a valid ICONDIR');
        $png = (string) ($this->resp('/global-protect/portal/images/bg.png')->body ?? '');
        self::assertSame("\x89PNG\r\n\x1a\n", substr($png, 0, 8), 'bg.png must be a valid PNG');
    }
}
