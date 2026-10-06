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
 * FP-0397 Part 1: the vulnerable-JavaScript asset feeder. Serves retire.js/OSV-flagged library versions
 * at canonical vendor paths so retire.js / ZAP / Burp confirm a vulnerable library. The version is the
 * real flagged literal, the banner the genuine product string (product-intrinsic, not a scanner
 * signature), Content-Type application/javascript. Route-tier → serves on an EMBEDDED host (no attack
 * emulation needed). The client-side beacon trap (Part 2) was dropped as out of core scope.
 */
final class VulnerableJsAssetFeederTest extends TestCase
{
    /** @var array<string,mixed>|null */
    private static $index;

    /** Route tier, attackEmulation OFF — proves the decoy serves on an embedded deployment. */
    private function engine(): Honeypot
    {
        if (self::$index === null) {
            self::$index = require __DIR__ . '/../resources/compiled/nuclei-index.full.php';
        }

        return new Honeypot(
            new PhpArrayStore(self::$index),
            new Config('respond', static fn (RequestContext $r): bool => true, 'matched-only',
                static fn (RequestContext $r): string => 'fixed', 'coherent', Style::REALISTIC, 'high')
        );
    }

    /**
     * @return array<string,array{0:string,1:string,2:string}> label => [path, versionMarker, retireRegex]
     * The retireRegex mirrors how retire.js reads the library version from the served bytes.
     */
    public function assets(): array
    {
        return [
            'jquery'        => ['/js/jquery-1.8.2.min.js', '1.8.2', '~jquery[^0-9]*?1\.8\.2~i'],
            'jquery-alias'  => ['/js/jquery.min.js', '1.8.2', '~jquery[^0-9]*?1\.8\.2~i'],
            'angular'       => ['/js/angular.min.js', '1.5.8', '~angularjs v1\.5\.8|full:"1\.5\.8"~i'],
            'lodash'        => ['/js/lodash.min.js', '4.17.4', '~lodash|VERSION="4\.17\.4"~i'],
            'lodash-vendor' => ['/assets/vendor/lodash.js', '4.17.4', '~VERSION="4\.17\.4"~'],
            'bootstrap'     => ['/js/bootstrap.min.js', '3.3.7', '~bootstrap v3\.3\.7~i'],
        ];
    }

    /** @dataProvider assets */
    public function test_vulnerable_library_is_served_and_retirejs_confirmable(string $path, string $version, string $retireRegex): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', $path, '', [], null, 'x.test'));
        self::assertNotNull($r, "{$path} must serve a vulnerable-library decoy on an embedded host");
        self::assertSame(200, $r->status);
        self::assertStringContainsString('application/javascript', $r->headers['Content-Type'] ?? '',
            'a .js asset must be served as application/javascript (invariant #5)');
        self::assertStringContainsString($version, $r->body, "the flagged version {$version} must appear");
        self::assertMatchesRegularExpression($retireRegex, $r->body, 'retire.js must be able to read the version');
    }

    public function test_jquery_carries_the_authentic_license_banner(): void
    {
        $r = $this->engine()->respond(new RequestContext('GET', '/js/jquery.min.js', '', [], null, 'x.test'));
        self::assertNotNull($r);
        self::assertStringContainsString('jquery.org/license', $r->body, 'the genuine jQuery license banner (product-intrinsic)');
        self::assertStringContainsString('jQuery v1.8.2', $r->body);
    }

    public function test_assets_carry_no_telemetry_beacon(): void
    {
        // Part 2 (the client-side sendBeacon/fetch canary trap) was dropped as out of core scope — the
        // body must be an inert library decoy, not an external-beacon instrument.
        foreach (['/js/jquery.min.js', '/js/angular.min.js', '/js/lodash.min.js', '/js/bootstrap.min.js'] as $p) {
            $r = $this->engine()->respond(new RequestContext('GET', $p, '', [], null, 'x.test'));
            self::assertNotNull($r);
            self::assertStringNotContainsString('sendBeacon', $r->body, "{$p} must carry no beacon");
            self::assertStringNotContainsString('/api/telemetry/canary', $r->body, "{$p} must carry no collector URL");
        }
    }
}
