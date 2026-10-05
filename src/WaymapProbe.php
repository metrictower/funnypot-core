<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Support\OobHaystack;

/**
 * FP-0415 Phase 1: a signal-only detector for Waymap v8 (TrixSec/waymap) scanner probes. Waymap emits
 * distinctive, near-unique markers in its injection payloads; recognising them lets the honeypot
 * ATTRIBUTE a scan (telemetry) without serving anything. Wired into classify() via OobSignalRegistry
 * and folded by foldOob(), so the baseline response stays BYTE-IDENTICAL — a Waymap probe gets exactly
 * the response a benign request would, so there is no differential "this endpoint reacts to my scanner
 * token" tell (security invariant #1).
 *
 * Clean-room: these are the TOOL'S OWN emitted tokens (facts re-derived from the public tool), MATCHED
 * here — never vendored code, never served. Detection-only: pure pattern matching over the bounded,
 * percent-decoded OobHaystack (path + query + every header value + body), no I/O / config / state (the
 * OobSignalRegistry contract). PHP 7.3-safe.
 */
final class WaymapProbe
{
    // Waymap's probe markers (research 2026-09-09 deep-dive, token table). `trixsec` is the author's
    // handle, so it is CRLF-context-gated (its CRLF-injection probe `…%0D%0AHeader-Test:trixsec`) to
    // avoid tagging a benign mention; OobHaystack decodes %0D%0A to \r\n, so both CRLF forms are
    // accepted. The WAYMAP_*/wymapxss/waymap_*/__proto__[waymap] markers are self-discriminating.
    // `wymapxss` is Waymap's actual emitted spelling (NOT a typo — do not "correct" it).
    private const PATTERN = '~(?:%0d%0a|[\r\n])[^\r\n]{0,40}trixsec'
        . '|WAYMAP_CMDI_[a-f0-9]{8}'
        . '|wymapxss[a-f0-9]+'
        . '|__proto__\[waymap\]'
        . '|WAYMAP_LFI_RCE'
        . '|waymap_(?:recon|lfi|cors)_~i';

    public static function detect(RequestContext $r): bool
    {
        return preg_match(self::PATTERN, OobHaystack::build($r)) === 1;
    }
}
