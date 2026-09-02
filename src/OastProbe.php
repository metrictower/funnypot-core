<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * Detect an out-of-band / SSRF probe anywhere in a request. Like Log4ShellProbe this is a DETECT-ONLY
 * signal: the exploit's proof is an out-of-band DNS/HTTP callback to the attacker's collaborator zone,
 * which a reflect-only responder cannot fake — so funnypot never "responds vulnerable", it just flags
 * the probe (high threat-intel value; these sprays otherwise slip past both the engine and the
 * fall-through classifier). Covers the common OAST collaborator zones (Burp, interactsh, ZAP, the
 * AI-agent AWS zone, dnslog/ceye) and the cloud-metadata SSRF endpoints (AWS/GCP/Alibaba IMDS).
 *
 * Returns a zone-family label (burp-collab / interactsh / zap-oast / aws-collab / dnslog /
 * cloud-metadata) or null. The label lives only in this detector's source — never in a served byte —
 * so it cannot fingerprint the honeypot, and the response is byte-identical whether or not it fires.
 */
final class OastProbe
{
    /**
     * Dot-prefixed zone substrings. The leading dot is the left-edge false-positive guard: a real
     * collaborator hit always carries a random subdomain label (`abc123.oastify.com`), so `roast.fun`
     * never matches `.oast.fun` and a bare vendor link in a Referer never matches. The matcher in
     * detect() adds the symmetric right-edge guard (the label must END after the zone, not continue
     * into another gTLD like `.oast.fund` / `.interact.shop`). Most-specific ordering is moot for
     * substrings (each is unique); first boundary-clean hit wins.
     * @var array<string,string>
     */
    private const ZONES = [
        '.oastify.com'          => 'burp-collab',
        '.burpcollaborator.net' => 'burp-collab',
        '.interact.sh'          => 'interactsh',
        '.interactsh.com'       => 'interactsh',
        '.oast.pro'             => 'interactsh',
        '.oast.live'            => 'interactsh',
        '.oast.site'            => 'interactsh',
        '.oast.online'          => 'interactsh',
        '.oast.fun'             => 'interactsh',
        '.oast.me'              => 'interactsh',
        '.dnslog.cn'            => 'dnslog',
        '.ceye.io'              => 'dnslog',
    ];

    /**
     * Cloud-metadata SSRF endpoints (link-local IMDS): AWS/GCP v4, AWS IPv6, Alibaba, and the GCP
     * metadata hostname. Plain substrings — no subdomain label to guard against.
     * @var array<string,string>
     */
    private const METADATA = [
        '169.254.169.254'          => 'cloud-metadata',
        'metadata.google.internal' => 'cloud-metadata',
        'fd00:ec2::254'            => 'cloud-metadata',
        '100.100.100.200'          => 'cloud-metadata',
    ];

    /**
     * Anchored, non-nested (ReDoS-safe) patterns for zones that need more than a substring:
     *  - ZAP plants a long numeric label under owasp.org; a bare owasp.org link (legit in UAs/Referers)
     *    must NOT match, so require >=8 leading digits.
     *  - The AI-agent AWS collaborator zone.
     * @var array<string,string>
     */
    private const PATTERNS = [
        '~\b\d{8,}\.owasp\.org\b~'          => 'zap-oast',
        '~collabp-reg\d+\.devops\.aws\.dev~' => 'aws-collab',
    ];

    public static function detect(RequestContext $r): ?string
    {
        // OOB payloads are planted anywhere: query, body, or a header (Referer, User-Agent,
        // X-Forwarded-For). The shared OobHaystack builds one capped, header-first haystack (raw
        // bytes); the casing + URL-decoded-copy post-processing is probe-local — lowercase, then
        // append a rawurldecode copy so a %2F-encoded SSRF URL is caught too.
        $hay = strtolower(OobHaystack::raw($r));
        $hay .= ' ' . rawurldecode($hay);

        foreach (self::PATTERNS as $pattern => $label) {
            if (preg_match($pattern, $hay) === 1) {
                return $label;
            }
        }
        foreach (self::ZONES as $needle => $label) {
            // Right-edge guard, mirroring the leading-dot left-edge guard: a real collaborator host
            // ends the zone label (`.oast.fun/…`, `.oast.fun:1337`, or end-of-string), whereas a
            // legitimate domain that merely STARTS with the zone word continues the label with another
            // domain char (`.oast.fund`, `.interact.shop`, `.interact.show` — all live gTLDs). Require
            // the char after the needle to not be a domain-label char (alnum or `-`). Scan every
            // occurrence, not just the first, so a benign superset earlier in the haystack cannot mask
            // a real collaborator hit later.
            $off = 0;
            while (($p = strpos($hay, $needle, $off)) !== false) {
                $next = $hay[$p + strlen($needle)] ?? ' ';
                if (!ctype_alnum($next) && $next !== '-') {
                    return $label;
                }
                $off = $p + 1;
            }
        }
        foreach (self::METADATA as $needle => $label) {
            if (strpos($hay, $needle) !== false) {
                return $label;
            }
        }

        return null;
    }
}
