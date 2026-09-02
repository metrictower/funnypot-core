<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\RequestContext;

/**
 * The shared, capped, HEADER-FIRST scan haystack for the OOB signal probes (FP-0256, extended
 * by FP-0257).
 *
 * Two layers:
 *  - raw(): the assembly layer. One capped string over every plantable request field, in a
 *    deterministic order: path, then query, then every header VALUE, then the body LAST — with
 *    PER-FIELD caps and a final TOTAL_CAP ceiling. OOB payloads (JNDI lookups, OAST collaborator
 *    URLs) overwhelmingly ride in headers (User-Agent / Referer / X-Api-Version), so scanning
 *    headers BEFORE the body means a >=16 KB junk body can no longer push them past the cap —
 *    that is the cap-ordering evasion this builder fixes.
 *  - build(): the scan layer. strtolower(raw()) plus a bounded, deterministic multi-URL-decode
 *    (up to MAX_DECODE_PASSES passes, stopping early at a decode fixpoint or when no percent-octet
 *    survives), each distinct layer appended with a ' ' separator. This closes the single-decode
 *    evasion (double-/triple-encoded payloads survived one rawurldecode). Both probes call build();
 *    lowercasing is harmless to Log4ShellProbe (its regex is /i) and decoding only widens coverage.
 *
 * THE HEADER-SECTION BUDGET (FP-0257 N1): headers-first alone creates a MIRROR residual — junk
 * HEADERS could then displace the BODY past the cap. Per-header value caps do not bound the header
 * COUNT (Apache's default 100 x 8 KB would let >20 junk 2 KB headers evict the body scan). So the
 * header SECTION is itself budgeted to HEADER_SECTION_CAP = TOTAL_CAP - PATH_CAP - QUERY_CAP -
 * BODY_CAP, which reserves the full BODY_CAP window at the tail: neither an oversized body nor
 * oversized/numerous headers can now displace the other field's scan window. Strictly better than
 * the baseline (a body-first, cap-after builder) in both directions.
 *
 * ACCEPTED RESIDUAL (documented, test-pinned): a payload buried deeper than BODY_CAP in the body,
 * or past HEADER_VALUE_CAP inside one giant header value, is still unscanned — the cap is a feature
 * (authored matchers vs unbounded attacker input), and some field always loses when the request
 * exceeds the total. What an attacker can no longer do is use the body to blind the header scan.
 *
 * Deterministic (pure function of the request snapshot; header iteration order is the adapter-built
 * array order, part of the request bytes), no I/O. build()'s output is bounded by
 * (1 + MAX_DECODE_PASSES) x TOTAL_CAP = 256 KB absolute worst case (approximately; the bound omits
 * the per-layer separator bytes) — rawurldecode never grows a string and the pass count is a
 * compile-time constant, so the multi-decode is DoS-safe.
 */
final class OobHaystack
{
    /** Per-header VALUE cap (values only, as the probes scan header values, not names). */
    public const HEADER_VALUE_CAP = 2048;

    /** Per-field caps for the request line. */
    public const PATH_CAP = 2048;
    public const QUERY_CAP = 4096;

    /** Body scan depth — unchanged from the baseline single 16 KB cap. */
    public const BODY_CAP = 16384;

    /** Final safety ceiling on the assembled raw() string (matches fromGlobals body cap). */
    public const TOTAL_CAP = 65536;

    /**
     * The whole header SECTION is budgeted so oversized/numerous headers cannot displace the body
     * past TOTAL_CAP (N1): TOTAL_CAP - PATH_CAP - QUERY_CAP - BODY_CAP reserves BODY_CAP at the tail.
     */
    public const HEADER_SECTION_CAP = self::TOTAL_CAP - self::PATH_CAP - self::QUERY_CAP - self::BODY_CAP;

    /** Bounded multi-decode ceiling: catches double- and triple-encoding, deterministic + DoS-safe. */
    public const MAX_DECODE_PASSES = 3;

    /**
     * Assembly layer: the capped, header-first raw haystack. Raw bytes only — casing and
     * URL-decoding are build()'s job.
     */
    public static function raw(RequestContext $r): string
    {
        $path = self::clip($r->path, self::PATH_CAP);
        $query = self::clip($r->query, self::QUERY_CAP);

        // Header section: each value capped, and the section as a whole bounded to HEADER_SECTION_CAP
        // so oversized or numerous headers can never displace the body past TOTAL_CAP (N1).
        $headers = '';
        foreach ($r->headers as $value) {
            $headers .= ' ' . self::clip((string) $value, self::HEADER_VALUE_CAP);
            if (strlen($headers) >= self::HEADER_SECTION_CAP) {
                $headers = substr($headers, 0, self::HEADER_SECTION_CAP);
                break;
            }
        }

        $body = self::clip((string) ($r->rawBody ?? ''), self::BODY_CAP);

        $hay = $path . ' ' . $query . $headers . ' ' . $body;

        return strlen($hay) > self::TOTAL_CAP ? substr($hay, 0, self::TOTAL_CAP) : $hay;
    }

    /**
     * Scan layer: lowercased raw() plus a bounded multi-URL-decode. The base is scanned as-is, then
     * each successive rawurldecode layer (up to MAX_DECODE_PASSES) is appended with a ' ' separator
     * — the separator is a non-domain char, so the probes' right-edge guards keep working across
     * layer boundaries. Stops early at a decode fixpoint or when no `%[0-9a-f]{2}` octet survives.
     */
    public static function build(RequestContext $r): string
    {
        $base = strtolower(self::raw($r));

        $scan = $base;
        $layer = $base;
        for ($i = 0; $i < self::MAX_DECODE_PASSES; $i++) {
            // A layer with no surviving percent-octet cannot decode further — fixpoint, stop.
            if (preg_match('~%[0-9a-f]{2}~', $layer) !== 1) {
                break;
            }
            $decoded = rawurldecode($layer);
            if ($decoded === $layer) {
                break;
            }
            $scan .= ' ' . $decoded;
            $layer = $decoded;
        }

        return $scan;
    }

    private static function clip(string $s, int $cap): string
    {
        return strlen($s) > $cap ? substr($s, 0, $cap) : $s;
    }
}
