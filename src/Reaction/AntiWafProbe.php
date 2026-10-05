<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

use Funnypot\Core\RequestContext;
use Funnypot\Core\Support\BoundedInspection;

/**
 * FP-0425 — recognise sqlmap's two fixed reconnaissance probes so the engine stays "blinded": it serves
 * the route's own baseline (never a 403/drop/error) for the WAF-check polyglot, keeping sqlmap in default
 * mode (no tamper/evasion scripts) so its later attack traffic flows into the differential decoys.
 *
 * Pure, stateless, zero-exec string work over the folded (double-decoded) request surface — no DNS, no
 * fetch, no reflection. The recogniser only ever SUPPRESSES a reaction (makes funnypot look unprotected);
 * a miss fails OPEN to the normal decoy pipeline, so it can never weaken real attack detection.
 */
final class AntiWafProbe
{
    /**
     * sqlmap's fixed `IPS_WAF_CHECK_PAYLOAD` (lib/core/settings.py). Match on the CO-OCCURRENCE of three
     * distinctive fixed literals that ONLY this one polyglot carries together — a generic
     * `union select … information_schema` SQLi never carries the `xp_cmdshell` cat-passwd gadget AND the
     * exact `<script>alert("XSS")</script>` literal, so the honeypot's own SQLi decoys are NOT blinded for
     * a real attacker. All three are required (AND); a 2-of-3 / partial match must NOT suppress. Any miss
     * (e.g. a tamper that rewrote a fragment) fails open to the normal decoy. Three independent stripos
     * calls — no spanning regex, so no catastrophic backtracking; bounded by the folded-surface cap.
     */
    public static function isWafCheckPolyglot(RequestContext $r): bool
    {
        $s = BoundedInspection::surface($r, 'request');
        if ($s === '') {
            return false;
        }

        return stripos($s, 'information_schema.tables') !== false
            && stripos($s, 'xp_cmdshell') !== false
            && stripos($s, '<script>alert("xss")</script>') !== false;
    }

    /**
     * sqlmap's preliminary `HEURISTIC_CHECK_ALPHABET`: a param VALUE that is exactly 10 chars drawn from
     * `" ' ) ( , .` and contains EXACTLY one single-quote and one double-quote (`^[",().']{10}$`). Telemetry
     * only — the caller tags the session and serves the UNCHANGED baseline (a special page would itself be a
     * tell). Checked per decoded query/form-body value (length-bounded to 10), never over the whole surface.
     */
    public static function isHeuristicAlphabet(RequestContext $r): bool
    {
        foreach (self::paramValues($r) as $v) {
            if (strlen($v) !== 10) {
                continue;
            }
            if (preg_match('~^[",().\']{10}$~', $v) !== 1) {
                continue;
            }
            if (substr_count($v, "'") === 1 && substr_count($v, '"') === 1) {
                return true;
            }
        }

        return false;
    }

    /** Max `&`-segments scanned per arm — the heuristic probe is a single short value; a bound keeps this
     *  linear and, crucially, avoids PHP's `parse_str` (its >max_input_vars WARNING throws under an embedded
     *  Laravel/Symfony warning-to-exception handler → a 500, which is itself a tell). Mirrors the codebase's
     *  deliberate no-`parse_str` rule (see QueryIntentClassifier / ParamMiningProbe). */
    private const MAX_SEGMENTS = 512;

    /**
     * The exactly-10-char decoded scalar values from the query and (when form-encoded) the body — the only
     * shape the heuristic alphabet can take. A bounded manual split (NO parse_str): never throws, never a
     * 500, linear in the capped segment count.
     *
     * @return list<string>
     */
    private static function paramValues(RequestContext $r): array
    {
        $out = [];
        self::collect($r->query ?? '', $out);
        $body = $r->rawBody;
        if ($body !== null && $body !== '' && strpos($body, '=') !== false && strpos($body, '{') === false) {
            self::collect($body, $out);
        }

        return $out;
    }

    /** @param list<string> $out */
    private static function collect(string $encoded, array &$out): void
    {
        if ($encoded === '') {
            return;
        }
        $segments = explode('&', $encoded, self::MAX_SEGMENTS + 1);
        $count = 0;
        foreach ($segments as $seg) {
            if (++$count > self::MAX_SEGMENTS) {
                break;
            }
            $eq = strpos($seg, '=');
            $raw = $eq === false ? $seg : substr($seg, $eq + 1);
            if ($raw === '') {
                continue;
            }
            // Form semantics: `+` is a space, then percent-decode — one decode, as the probe is sent with.
            $value = urldecode($raw);
            if (strlen($value) === 10) {
                $out[] = $value; // only the 10-char candidate can be the heuristic alphabet
            }
        }
    }
}
