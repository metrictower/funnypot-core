<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use Funnypot\Core\OastProbe;
use Funnypot\Core\RequestContext;
use PHPUnit\Framework\TestCase;

final class OastProbeTest extends TestCase
{
    public function test_detects_collaborator_zones_by_family(): void
    {
        $cases = [
            ['q=url=http://abc123.oastify.com/x', 'burp-collab'],
            ['q=http://x.burpcollaborator.net/', 'burp-collab'],
            ['q=http://cxyz.oast.fun/a', 'interactsh'],
            ['q=http://a.interact.sh/', 'interactsh'],
            ['q=http://a.dnslog.cn/', 'dnslog'],
            ['q=http://4232278668650001277.owasp.org/', 'zap-oast'],
            ['q=x.PEN-1-2.dns.collabp-reg4.devops.aws.dev', 'aws-collab'],
            ['q=x.PEN-9.dns.collabp-reg7.devops.aws.dev', 'aws-collab'],
            ['q=url=http://169.254.169.254/latest/meta-data/iam/', 'cloud-metadata'],
            ['q=url=http://metadata.google.internal/computeMetadata/v1/', 'cloud-metadata'],
        ];
        foreach ($cases as [$query, $expected]) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame($expected, OastProbe::detect($r), "query: {$query}");
        }
    }

    public function test_detects_zone_in_any_request_field(): void
    {
        // Referer header only.
        self::assertSame('burp-collab', OastProbe::detect(
            new RequestContext('GET', '/', '', ['Referer' => 'http://z.oastify.com/'])
        ));
        // User-Agent only.
        self::assertSame('interactsh', OastProbe::detect(
            new RequestContext('GET', '/', '', ['User-Agent' => 'probe http://q.oast.pro/'])
        ));
        // POST body (XXE external entity).
        self::assertSame('burp-collab', OastProbe::detect(
            new RequestContext('POST', '/', '', [], '<!ENTITY x SYSTEM "http://e.oastify.com/">')
        ));
        // URL-encoded query (SSRF to IMDS).
        self::assertSame('cloud-metadata', OastProbe::detect(
            new RequestContext('GET', '/', 'url=http%3A%2F%2F169.254.169.254%2Flatest%2F')
        ));
        // Path segment.
        self::assertSame('interactsh', OastProbe::detect(
            new RequestContext('GET', '/redirect/http://p.interact.sh/')
        ));
    }

    public function test_false_positive_guards(): void
    {
        // Plain benign request.
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', 'q=hello', ['User-Agent' => 'curl/8.0'])));
        // A legit OWASP link (no long numeric label) must not match zap-oast.
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', '', ['Referer' => 'https://owasp.org/www-project-zap/'])));
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', '', ['User-Agent' => 'links (www.owasp.org)'])));
        // The dot-prefix (left-edge) guard: a domain that merely ends in the zone word must not match.
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', 'q=http://x.roast.fun/')));
        // The right-edge guard: a live gTLD that merely STARTS with a collaborator zone must not
        // match (`.oast.fund`, `.interact.shop`, `.interact.show`, `.oast.melbourne` are real,
        // plausible legit domains — not interactsh hosts).
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', 'u=https://x.oast.fund/')));
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', '', ['Referer' => 'https://www.interact.shop/checkout'])));
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', 'u=https://app.interact.show/')));
        self::assertNull(OastProbe::detect(new RequestContext('GET', '/', 'ref=https://my.oast.melbourne.example/')));
    }

    public function test_boundary_clean_hit_beside_a_benign_superset_still_fires(): void
    {
        // A right-edge-guarded superset (`.oast.fund`) earlier in the haystack must NOT mask a real
        // boundary-clean collaborator hit (`.oast.fun/`) later — the matcher scans every occurrence.
        self::assertSame('interactsh', OastProbe::detect(
            new RequestContext('GET', '/', 'a=https://x.oast.fund/&b=https://real.oast.fun/')
        ));
        // Zone at end-of-haystack (no trailing char) is still a clean boundary.
        self::assertSame('interactsh', OastProbe::detect(
            new RequestContext('GET', '/', 'u=abc.oast.fun')
        ));
    }

    public function test_payload_past_the_cap_is_not_scanned(): void
    {
        // Documents the 16KB cap: a zone buried past it in the body is not matched.
        $body = str_repeat('A', 16400) . 'http://late.oastify.com/';
        self::assertNull(OastProbe::detect(new RequestContext('POST', '/', '', [], $body)));
    }
}
