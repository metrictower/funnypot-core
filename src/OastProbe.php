<?php

declare(strict_types=1);

namespace Funnypot\Core;

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
     * Dot-prefixed zone substrings. The leading dot is the false-positive guard: a real collaborator
     * hit always carries a random subdomain label (`abc123.oastify.com`), so `roast.fun` never matches
     * `.oast.fun` and a bare vendor link in a Referer never matches. Most-specific ordering is moot for
     * substrings (each is unique); first hit wins.
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
        // X-Forwarded-For). Build one haystack, cap it (authored matchers vs attacker input), lowercase,
        // and append a URL-decoded copy so a %2F-encoded SSRF URL is caught too.
        $hay = $r->path . ' ' . $r->query . ' ' . (string) ($r->rawBody ?? '');
        foreach ($r->headers as $value) {
            $hay .= ' ' . (string) $value;
        }
        if (strlen($hay) > 16384) {
            $hay = substr($hay, 0, 16384);
        }
        $hay = strtolower($hay);
        $hay .= ' ' . rawurldecode($hay);

        foreach (self::PATTERNS as $pattern => $label) {
            if (preg_match($pattern, $hay) === 1) {
                return $label;
            }
        }
        foreach (self::ZONES as $needle => $label) {
            if (strpos($hay, $needle) !== false) {
                return $label;
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
