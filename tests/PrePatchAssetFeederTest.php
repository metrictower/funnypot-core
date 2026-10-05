<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\Config;
use Funnypot\Core\Honeypot;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Response\Style;
use Funnypot\Core\Store\PhpArrayStore;
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
    // The valid pre-patch Last-Modified epochs (must mirror PersonaIdentity::CITRIX_BUILDS / IVANTI_BUILDS).
    private const CITRIX_EPOCHS = [1684108800, 1681084800, 1691366400];
    private const IVANTI_EPOCHS = [1687219200, 1694476800, 1698105600];

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
