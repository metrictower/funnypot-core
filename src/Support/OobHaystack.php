<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\RequestContext;

/**
 * The shared, capped, HEADER-FIRST scan haystack for the OOB signal probes (FP-0256).
 *
 * One capped string over every plantable request field, in a deterministic order:
 * path, then query, then every header VALUE, then the body LAST — then the cap.
 * OOB payloads (JNDI lookups, OAST collaborator URLs) overwhelmingly ride in headers
 * (User-Agent / Referer / X-Api-Version), so scanning headers BEFORE the body means a
 * >=16 KB junk body can no longer push them past the cap — that is the cap-ordering
 * evasion this builder fixes.
 *
 * ACCEPTED TRADE (not "body posture unchanged"): putting headers first shrinks the
 * body-scan window to `CAP - len(path + query + header values)`. So the fix is
 * symmetric — oversized HEADERS can now push a BODY payload past the 16 KB cap, exactly
 * the way an oversized body used to push a header payload past it. Headers are the
 * protected field by deliberate choice (§8): OOB payloads live there far more often than
 * in the body, and the cap is a feature (authored matchers vs unbounded attacker input),
 * not a bug — some field always loses when the request exceeds it.
 *
 * Raw bytes only: casing and URL-decoding variants are each probe's own business
 * (OastProbe lowercases + appends a rawurldecode copy; Log4ShellProbe matches
 * case-insensitively). Deterministic (pure function of the request snapshot; header
 * iteration order is the adapter-built array order, part of the request bytes), no I/O,
 * bounded output (<= CAP bytes).
 */
final class OobHaystack
{
    /** Scan cap: authored matchers vs unbounded attacker input; a probe payload is short. */
    public const CAP = 16384;

    public static function raw(RequestContext $r): string
    {
        $hay = $r->path . ' ' . $r->query;
        foreach ($r->headers as $value) {
            $hay .= ' ' . (string) $value;
        }
        $hay .= ' ' . (string) ($r->rawBody ?? '');

        return strlen($hay) > self::CAP ? substr($hay, 0, self::CAP) : $hay;
    }
}
