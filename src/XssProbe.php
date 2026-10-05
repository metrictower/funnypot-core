<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * FP-0474 Phase 1: a signal-only detector for automated XSS scanners (Dalfox / XSStrike) from their
 * UNIQUE marker sentinels. Wired into classify() via OobSignalRegistry and folded by foldOob(), so the
 * baseline response is BYTE-IDENTICAL — attribution/telemetry only, nothing served changes (security
 * invariant #1). Same proven architecture as WaymapProbe (FP-0415).
 *
 * Clean-room: these are the scanners' OWN injected marker tokens (facts), MATCHED here — never served.
 * Detection-only, pure pattern matching over the bounded, percent-decoded OobHaystack (path + query +
 * header values + body), no I/O / config / state (the OobSignalRegistry contract). PHP 7.3-safe.
 *
 * Markers (grounded in the funnypot-project scanner-confirmation clean-room analysis — a PRIVATE
 * sibling repo, so no path is cited here; verified against the real Dalfox source, src/scanning/
 * markers.rs): Dalfox's dominant discovery marker is a CONCATENATED bracketed sandwich with NO
 * separators — `dlx<hex>dlxmid<hex>xld<hex>` — plus the standalone `dlfx_sentinel…` sentinel and
 * `.dalfox`/`#dalfox` class/id markers. We match those tool-unique forms.
 *
 * FP discipline (the FP-0436/FP-0426 lesson): only DISTINCTIVE forms are matched — the `dlfx_sentinel`
 * literal, the `dlxmid`+hex inner marker (UN-anchored so it catches the concatenated sandwich, where
 * every junction is word-char→word-char and a leading `\b` could never anchor), a `dlx`/`xld` prefix
 * followed by a hex run, and `dalfox` ONLY in a css-selector / html-attribute marker position
 * (`.dalfox`/`#dalfox`/`class=dalfox`/`id=dalfox`) — NOT a bare query param `?q=dalfox`, which is a
 * benign search for the tool's name. The analysis lists a bare static
 * marker `90197752`, and the ticket adds a "≥15 special characters" batched-probe heuristic; both are
 * DELIBERATELY NOT matched — a bare 8-digit number FPs on benign numeric ids, a special-char density
 * count FPs on benign regex/JSON/minified-JS, and a bare `dalfox` mention FPs on security-report text.
 * A honeypot that fakes an XSS finding on benign traffic is a tell; recall on those is traded for a
 * zero-FP signal. (The CONFIRMING reflector is the separate, deferred Part-2 work; the shipped 64/65
 * reflectors already cover the owned-path reflection baseline.)
 */
final class XssProbe
{
    private const PATTERN = '~\bdlfx_sentinel|dlxmid[0-9a-f]{4,}|(?:[.#]|(?:class|id)=[\x22\x27]?)dalfox\b|\b(?:dlx|xld)[0-9a-f]{4,}\b~i';

    public static function detect(RequestContext $r): bool
    {
        return preg_match(self::PATTERN, OobHaystack::build($r)) === 1;
    }
}
