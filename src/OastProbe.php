<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * Detect an out-of-band / SSRF probe anywhere in a request. Like Log4ShellProbe this is a DETECT-ONLY
 * signal: the exploit's proof is an out-of-band DNS/HTTP callback to the attacker's collaborator zone,
 * which a reflect-only responder cannot fake — so funnypot never "responds vulnerable", it just flags
 * the probe (high threat-intel value; these sprays otherwise slip past both the engine and the
 * fall-through classifier). Coverage (FP-0257): the OAST collaborator zones (Burp, interactsh, ZAP,
 * the AI-agent AWS zone, dnslog/ceye), blind-XSS (bxss.me/r87.me), canarytokens, webhook.site
 * exfiltration, the cloud-metadata SSRF endpoints incl. IMDS IP-encoding variants (AWS/GCP/Alibaba/
 * Azure/ECS), the XXE-OOB external-entity shape, the generic JNDI/deserialization resolver scheme
 * (ldap/rmi/iiop), and DNS-rebinding hint zones (nip.io/sslip.io/rbndr.us).
 *
 * detect() returns a zone-family label (or null); matchFor() maps that label to the per-family
 * TemplateMatch (id / severity / tags) the OobSignalRegistry folds. The label lives only in this
 * detector's source — never in a served byte — so it cannot fingerprint the honeypot, and the
 * response is byte-identical whether or not it fires. Pure string / pattern matching over the
 * shared, capped, header-first OobHaystack::build() (lowercased + bounded multi-URL-decode) — no I/O,
 * deterministic.
 */
final class OastProbe
{
    /**
     * Dot-prefixed collaborator / probe zone substrings (HIGH severity). The leading dot is the
     * left-edge false-positive guard: a real hit always carries a random subdomain label
     * (`abc123.oastify.com`, `<uuid>.webhook.site`), so `roast.fun` never matches `.oast.fun` and a
     * bare vendor link in a Referer never matches. detect() adds the symmetric right-edge guard (the
     * label must END after the zone, not continue into another gTLD like `.oast.fund` /
     * `.interact.shop`). First boundary-clean hit wins.
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
        '.canarytokens.com'     => 'canarytokens',
        '.webhook.site'         => 'webhook-exfil',
        '.bxss.me'              => 'blind-xss',
        '.r87.me'               => 'blind-xss',
    ];

    /**
     * DNS-rebinding hint zones (MEDIUM). A rebinding host is `<ip-or-label>.nip.io` with the zone as
     * the registrable trailing domain, so these carry a STRICTER right-edge guard than the
     * collaborator zones: a following `.label` (`x.nip.io.example`) means the zone is NOT the
     * registrable domain and must not fire. Scanned LAST (severity-descending).
     * @var array<string,string>
     */
    private const REBIND_ZONES = [
        '.nip.io'   => 'dns-rebinding',
        '.sslip.io' => 'dns-rebinding',
        '.rbndr.us' => 'dns-rebinding',
    ];

    /**
     * Cloud-metadata SSRF endpoints (CRITICAL), link-local IMDS: AWS/GCP v4, AWS IPv6, Alibaba, the
     * GCP metadata hostname, the ECS task-metadata endpoint, and the IPv6-mapped form of
     * 169.254.169.254. Plain substrings — no subdomain label to guard against. (The dotted form
     * `::ffff:169.254.169.254` is already covered by the `169.254.169.254` substring — no entry.)
     * @var array<string,string>
     */
    private const METADATA = [
        '169.254.169.254'          => 'cloud-metadata',
        'metadata.google.internal' => 'cloud-metadata',
        'fd00:ec2::254'            => 'cloud-metadata',
        '100.100.100.200'          => 'cloud-metadata',
        '169.254.170.2'            => 'cloud-metadata', // ECS task-metadata / credentials endpoint
        '::ffff:a9fe:a9fe'         => 'cloud-metadata', // IPv6-mapped 169.254.169.254
    ];

    /**
     * Cloud-metadata endpoints/encodings needing lookaround guards (CRITICAL):
     *  - Azure wireserver 168.63.129.16 — MUST be a pattern, not a substring: 168.63.0.0/16 is
     *    routable Azure public space, so `(?!\d)` stops `168.63.129.167` false-flagging.
     *  - IMDS IP-encoding variants of 169.254.169.254 (0xA9FEA9FE): decimal, hex, per-octet hex,
     *    octal. Digit/hex-run lookarounds stop a longer number/hex-run that merely CONTAINS the
     *    value from matching (a lone hex/decimal hit inside a random token is ~1e-10, accepted).
     *    Overflowed/mixed-radix forms (425.510.425.510) are out of scope (endless space).
     * @var array<string,string>
     */
    private const METADATA_PATTERNS = [
        '~168\.63\.129\.16(?!\d)~'                     => 'cloud-metadata',
        '~(?<![0-9])2852039166(?![0-9])~'              => 'cloud-metadata', // decimal 0xA9FEA9FE
        '~0xa9fea9fe(?![0-9a-f])~'                      => 'cloud-metadata', // hex (right-guarded, N2)
        '~0xa9\.0xfe\.0xa9\.0xfe(?![0-9a-f])~'          => 'cloud-metadata', // per-octet hex (N2)
        '~(?<![0-9])0251\.0376\.0251\.0376(?![0-9])~'  => 'cloud-metadata', // octal
    ];

    /**
     * Anchored, non-nested (ReDoS-safe) patterns for zones/shapes that a substring can't express
     * (HIGH severity):
     *  - ZAP plants a long numeric label under owasp.org; a bare owasp.org link (legit in
     *    UAs/Referers) must NOT match, so require >=8 leading digits.
     *  - The AI-agent AWS collaborator zone.
     *  - blind-XSS (bxss.me / r87.me) and webhook.site used bare or path-style (`webhook.site/<uuid>`,
     *    `bxss.me/t/xss.js`) — the leading-dot ZONES entries only catch the subdomained form. The
     *    lookbehind excludes `.` on the left so the subdomained form is left to ZONES, while `/`, `:`
     *    and `=` on the left still match; the right guard mirrors the ZONES right-edge guard.
     *  - the XXE external-entity declaration shape (effectively never in legit traffic; a bare
     *    DOCTYPE with a system-id is NOT matched — legit XML carries w3.org DTD system ids).
     *  - the generic JNDI/deserialization resolver scheme (ldap/ldaps/rmi/iiop) that carries no
     *    `${…}` wrapper and so misses Log4ShellProbe (fastjson/Jackson gadget URLs). `jndi:` itself
     *    stays Log4ShellProbe's — the `${` wrapper is its evidence of a lookup. Left-boundary guard
     *    excludes an alnum/`-` prefix (`httpldap://`, `x-rmi://` do NOT match, N6).
     * @var array<string,string>
     */
    private const PATTERNS = [
        '~\b\d{8,}\.owasp\.org\b~'                                                                            => 'zap-oast',
        '~collabp-reg\d+\.devops\.aws\.dev~'                                                                  => 'aws-collab',
        '~(?<![a-z0-9.-])webhook\.site(?![a-z0-9-])~'                                                         => 'webhook-exfil',
        '~(?<![a-z0-9.-])bxss\.me(?![a-z0-9-])~'                                                              => 'blind-xss',
        '~(?<![a-z0-9.-])r87\.me(?![a-z0-9-])~'                                                               => 'blind-xss',
        '~<!entity\s[^>]{0,200}\bsystem\b[^>]{0,120}["\'](?:https?|ftp|file|php|expect|jar|netdoc|gopher):~'  => 'xxe-oob',
        '~(?<![a-z0-9-])(?:ldap|ldaps|rmi|iiop)://[^\s"\'<>\\\\]{1,256}~'                                     => 'jndi-oob',
    ];

    /**
     * Per-family match projection (id / severity / tags / name) the OobSignalRegistry folds. The
     * collaborator families keep the pre-FP-0257 shape (id `oast-callback`, high,
     * `[oast-callback, <family>, ssrf, oob]`). cloud-metadata is retagged: it is an SSRF TARGET, not
     * a callback, so id `cloud-metadata-ssrf` + severity critical (§8: "IMDS = critical") — but the
     * legacy `oast-callback` tag is KEPT for one deprecation release to soften the alerting/veto
     * exposure (drop it in a follow-up). xxe-oob / jndi-oob / dns-rebinding get their own ids so
     * policy can weight them independently; dns-rebinding is a medium HINT, not a callback.
     * @var array<string,array{0:string,1:string,2:string[],3:string}>
     */
    private const FAMILIES = [
        'burp-collab'    => ['oast-callback',       'high',     ['oast-callback', 'burp-collab', 'ssrf', 'oob'],             'OAST/OOB collaborator callback'],
        'interactsh'     => ['oast-callback',       'high',     ['oast-callback', 'interactsh', 'ssrf', 'oob'],              'OAST/OOB collaborator callback'],
        'zap-oast'       => ['oast-callback',       'high',     ['oast-callback', 'zap-oast', 'ssrf', 'oob'],                'OAST/OOB collaborator callback'],
        'aws-collab'     => ['oast-callback',       'high',     ['oast-callback', 'aws-collab', 'ssrf', 'oob'],              'OAST/OOB collaborator callback'],
        'dnslog'         => ['oast-callback',       'high',     ['oast-callback', 'dnslog', 'ssrf', 'oob'],                  'OAST/OOB collaborator callback'],
        'blind-xss'      => ['oast-callback',       'high',     ['oast-callback', 'blind-xss', 'xss', 'oob'],                'Blind-XSS OOB collaborator callback'],
        'canarytokens'   => ['oast-callback',       'high',     ['oast-callback', 'canarytoken', 'oob'],                     'Canarytoken OOB callback'],
        'webhook-exfil'  => ['oast-callback',       'high',     ['oast-callback', 'webhook-exfil', 'oob'],                   'Webhook exfiltration OOB callback'],
        'cloud-metadata' => ['cloud-metadata-ssrf', 'critical', ['cloud-metadata', 'imds', 'ssrf', 'oob', 'oast-callback'],  'Cloud-metadata IMDS SSRF target'],
        'xxe-oob'        => ['xxe-oob',             'high',     ['xxe', 'xxe-oob', 'oob'],                                    'XXE out-of-band external entity'],
        'jndi-oob'       => ['jndi-oob',            'high',     ['jndi', 'jndi-oob', 'deserialization', 'oob'],               'JNDI/deserialization resolver OOB'],
        'dns-rebinding'  => ['dns-rebinding-hint',  'medium',   ['dns-rebinding', 'ssrf', 'oob-hint'],                        'DNS-rebinding hint'],
    ];

    public static function detect(RequestContext $r): ?string
    {
        // OOB payloads are planted anywhere: query, body, or a header (Referer, User-Agent,
        // X-Forwarded-For). OobHaystack::build() is one capped, header-first haystack, lowercased and
        // bounded-multi-URL-decoded, so a %2F- (or double-)encoded SSRF URL is caught too.
        $hay = OobHaystack::build($r);

        // Severity-descending scan (§2.4g): cloud-metadata (critical) -> high patterns/zones ->
        // dns-rebinding (medium). First hit in a fixed order wins, so a rebinding-style IMDS probe
        // (169.254.169.254.nip.io) reports critical cloud-metadata, not the medium rebinding hint.
        foreach (self::METADATA as $needle => $label) {
            if (strpos($hay, $needle) !== false) {
                return $label;
            }
        }
        foreach (self::METADATA_PATTERNS as $pattern => $label) {
            if (preg_match($pattern, $hay) === 1) {
                return $label;
            }
        }

        // High-severity collaborator/probe zones BEFORE the high PATTERNS, so a collaborator host
        // wins over the broader xxe-oob/jndi-oob resolver shapes when one body carries both (an XXE
        // entity or JNDI lookup pointing AT a Burp collaborator stays the collaborator family).
        $zone = self::scanZones($hay, self::ZONES, false);
        if ($zone !== null) {
            return $zone;
        }

        foreach (self::PATTERNS as $pattern => $label) {
            if (preg_match($pattern, $hay) === 1) {
                return $label;
            }
        }

        // DNS-rebinding hint (medium), stricter right edge (see REBIND_ZONES doc).
        return self::scanZones($hay, self::REBIND_ZONES, true);
    }

    /**
     * The per-family TemplateMatch for a detect() label. Unknown labels fall back to the legacy
     * collaborator shape (defensive; every label detect() returns is in FAMILIES).
     */
    public static function matchFor(string $family): TemplateMatch
    {
        $spec = self::FAMILIES[$family]
            ?? ['oast-callback', 'high', ['oast-callback', $family, 'ssrf', 'oob'], 'OAST/OOB collaborator callback'];

        return new TemplateMatch($spec[0], $spec[1], $spec[2], $spec[3]);
    }

    /**
     * Scan dot-prefixed zones with the right-edge guard. A real collaborator host ENDS the zone label
     * (`.oast.fun/…`, `.oast.fun:1337`, or end-of-string), whereas a legitimate domain that merely
     * STARTS with the zone word continues the label with another domain char (`.oast.fund`). Require
     * the char after the needle to not be a domain-label char (alnum or `-`); with $strictRightEdge a
     * following `.` is ALSO a continuation (rebinding zones must be the registrable trailing domain).
     * Scan every occurrence, not just the first, so a benign superset earlier cannot mask a real hit.
     *
     * @param array<string,string> $zones
     */
    private static function scanZones(string $hay, array $zones, bool $strictRightEdge): ?string
    {
        foreach ($zones as $needle => $label) {
            $off = 0;
            while (($p = strpos($hay, $needle, $off)) !== false) {
                $next = $hay[$p + strlen($needle)] ?? ' ';
                $continues = ctype_alnum($next) || $next === '-' || ($strictRightEdge && $next === '.');
                if (!$continues) {
                    return $label;
                }
                $off = $p + 1;
            }
        }

        return null;
    }
}
