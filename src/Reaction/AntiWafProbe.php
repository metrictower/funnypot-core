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

    /**
     * Decoded scalar values from the query string and (when form-encoded) the body. parse_str urldecodes
     * once — the single decode the heuristic alphabet is sent with. Bounded: only values already short
     * enough to be the 10-char probe matter, and parse_str caps at max_input_vars.
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
        $parsed = [];
        parse_str($encoded, $parsed);
        array_walk_recursive($parsed, static function ($v) use (&$out): void {
            if (is_string($v)) {
                $out[] = $v;
            }
        });
    }
}
