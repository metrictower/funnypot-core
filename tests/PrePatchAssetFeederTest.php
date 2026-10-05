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
 * FP-0383: pre-patch Last-Modified static-asset feeder. The OWASP Nettacker `*_lastpatcheddate` recon
 * modules HEAD a vendor static asset and read `Last-Modified` to date the build; serving a date BEFORE
 * the vendor's CVE patch makes the scanner declare the host unpatched and proceed to exploit delivery
 * (into the decoys). Verified vendors: Citrix NetScaler (/epa/scripts/win/nsepa_setup.exe, CVE-2023-4966
 * patched 2023-10-10) and Ivanti Connect Secure (/dana-na/css/ds.js, CVE-2023-46805/-2024-21887 patched
 * 2024-01-31). The served date is always one of the deploy's vulnerable BUILDS entries (version<->date
 * coherent, pre-patch) across every seed.
 */
final class PrePatchAssetFeederTest extends TestCase
{
    private const CITRIX_PATCH = 1696896000;    // 2023-10-10
    private const IVANTI_PATCH = 1706659200;    // 2024-01-31
    private const CRUSHFTP_PATCH = 1742515200;  // 2025-03-21 (CVE-2025-31161)
    private const IVCSA_PATCH = 1725926400;     // 2024-09-10 (CVE-2024-8190/-2024-8963)
    private const AEM_PATCH = 1591660800;       // 2020-06-09 (APSB20-31 / SP 6.5.5.0)
    // The valid pre-patch Last-Modified epochs (must mirror the PersonaIdentity::*_BUILDS consts).
    private const CITRIX_EPOCHS = [1684108800, 1681084800, 1691366400];
    private const IVANTI_EPOCHS = [1687219200, 1694476800, 1698105600];
    private const CRUSHFTP_EPOCHS = [1734000000, 1738022400];
    private const IVCSA_EPOCHS = [1712707200, 1722470400];
    private const AEM_EPOCHS = [1554681600, 1576108800, 1583366400];

    /** @var array<string,mixed>|null */
    private static $idx;

    private function engine(): Honeypot
    {
        if (self::$idx === null) {
            self::$idx = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }
        $cfg = new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
            static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'critical',
            65536, 0, 0, false, null, null, null, 'fixed');

        return new Honeypot(new PhpArrayStore(self::$idx), $cfg);
    }

    private function serve(string $method, string $path, string $host): ?object
    {
        return $this->engine()->respond(new RequestContext($method, $path, '', [], null, $host));
    }

    private function lastModified(?object $r): ?string
    {
        if ($r === null) {
            return null;
        }

        return $r->headers['Last-Modified'] ?? $r->headers['last-modified'] ?? null;
    }

    /** @return array<string,array{0:string,1:string,2:int,3:list<int>}> */
    public function assets(): array
    {
        return [
            'citrix nsepa.exe' => ['/epa/scripts/win/nsepa_setup.exe', 'application/octet-stream', self::CITRIX_PATCH, self::CITRIX_EPOCHS],
            'ivanti ds.js'     => ['/dana-na/css/ds.js', 'application/javascript', self::IVANTI_PATCH, self::IVANTI_EPOCHS],
            'crushftp jar'     => ['/WebInterface/CrushTunnel.jar', 'application/java-archive', self::CRUSHFTP_PATCH, self::CRUSHFTP_EPOCHS],
            'ivanti-csa png'   => ['/allowed/ivanti-logo.png', 'image/png', self::IVCSA_PATCH, self::IVCSA_EPOCHS],
            'aem clientlib.js' => ['/libs/granite/core/content/login/clientlib.js', 'application/javascript', self::AEM_PATCH, self::AEM_EPOCHS],
        ];
    }

    /** @dataProvider assets */
    public function test_get_serves_a_prepatch_last_modified(string $path, string $ct, int $patch, array $epochs): void
    {
        $r = $this->serve('GET', $path, 'scan.example.test');
        self::assertNotNull($r, "{$path} must be served");
        self::assertSame(200, $r->status);
        $servedCt = $r->headers['Content-Type'] ?? $r->headers['content-type'] ?? '';
        self::assertSame($ct, $servedCt, 'Content-Type matches the asset type');
        $lm = $this->lastModified($r);
        self::assertNotNull($lm, 'serves a Last-Modified header');
        self::assertLessThan($patch, strtotime($lm), 'the build date is BEFORE the CVE patch (declares unpatched)');
        self::assertContains(strtotime($lm), $epochs, 'the date is one of the deploy vulnerable-build entries (version<->date coherent)');
    }

    /** @dataProvider assets */
    public function test_head_serves_the_same_prepatch_last_modified(string $path, string $ct, int $patch, array $epochs): void
    {
        // Nettacker uses HEAD; the engine answers HEAD against the GET route.
        $r = $this->serve('HEAD', $path, 'scan.example.test');
        self::assertNotNull($r, "{$path} must answer HEAD");
        self::assertSame(200, $r->status);
        $lm = $this->lastModified($r);
        self::assertNotNull($lm);
        self::assertLessThan($patch, strtotime($lm), 'HEAD date is pre-patch');
    }

    /**
     * version<->date same-entry coherence (plan v2): the resolved `<vendor>.version` and
     * `<vendor>.lastModified` must come from the SAME BUILDS entry, so a future surface that displays the
     * version can never disagree with the asset date. Known-answer map mirrors PersonaIdentity::CITRIX_BUILDS
     * / IVANTI_BUILDS — a refactor pointing `version` at a different pool fails this.
     */
    public function test_version_and_last_modified_are_the_same_build_entry(): void
    {
        $maps = [
            'citrix' => ['13.1-48.47' => 1684108800, '13.0-90.12' => 1681084800, '14.1-4.42' => 1691366400],
            'ivanti' => ['22.3R1' => 1687219200, '9.1R18.3' => 1694476800, '22.5R2.1' => 1698105600],
            'crushftp' => ['10.8.3' => 1734000000, '11.3.0' => 1738022400],
            'ivcsa' => ['4.6.511' => 1712707200, '5.0.1' => 1722470400],
            'aem' => ['6.5.0.0' => 1554681600, '6.5.3.0' => 1576108800, '6.5.4.0' => 1583366400],
        ];
        for ($s = 0; $s < 24; $s++) {
            $p = PersonaIdentity::fromSeed($s);
            foreach ($maps as $vendor => $map) {
                $ver = (string) $p->field("{$vendor}.version");
                $lm = (string) $p->field("{$vendor}.lastModified");
                self::assertArrayHasKey($ver, $map, "seed {$s}: {$vendor}.version is a known vulnerable build");
                self::assertSame($map[$ver], strtotime($lm), "seed {$s}: {$vendor} version<->lastModified are the same build entry");
            }
        }
    }

    /** Across many deploy seeds the served date is always a valid pre-patch build entry (never post-patch). */
    public function test_every_seed_serves_a_valid_prepatch_build(): void
    {
        foreach ($this->assets() as $label => [$path, , $patch, $epochs]) {
            for ($i = 0; $i < 24; $i++) {
                $lm = $this->lastModified($this->serve('GET', $path, "h{$i}.example.test"));
                self::assertNotNull($lm, "{$label} seed {$i} serves a Last-Modified");
                self::assertContains(strtotime($lm), $epochs, "{$label} seed {$i} date is a valid vulnerable build");
                self::assertLessThan($patch, strtotime($lm), "{$label} seed {$i} is pre-patch");
            }
        }
    }
}
