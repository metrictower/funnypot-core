<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

/**
 * FP-0427: detect an automated parameter-mining batch (sqlmap `--mine-params`, standalone Param Miner) and
 * steer it into a single honey-parameter. sqlmap batches PARAMETER_MINING_BUCKET_SIZE=25 candidate names
 * per request as `name=canary&…`, where each canary is `randomStr(10, lowercase)` — exactly `^[a-z]{10}$` —
 * and confirms a parameter as hidden when its canary appears VERBATIM in the response body but NOT in the
 * baseline page.
 *
 * This probe recognises the batch (≥ MINING_THRESHOLD params whose value is canary-shaped) AND a designated
 * honey-key, and returns a KIND_DEBUG_CANARY intent carrying ONLY that honey-key's canary. The reaction
 * renderer echoes that one canary (escaped — a no-op for `[a-z]{10}`, so it reflects verbatim), so sqlmap
 * confirms ONLY the honey-parameter, adds it to the GET set, and pours all subsequent SQLi testing into it —
 * which lands on the differential SQLi tarpit. The other candidates are never echoed, so they stay
 * unconfirmed. PURE: a function of the raw query string; no I/O, no superglobal, no `parse_str()`.
 *
 * Serving is gated exactly like every other reaction intent (paramReactivity && serveReflector('param-
 * reaction') => isolatedOrigin), so this is a dedicated-honeypot-box feature and NEVER fires on an embedded
 * host or the null-request synthesize() port.
 */
final class ParamMiningProbe
{
    private const MAX_QUERY_BYTES = 2048;
    private const MAX_PAIRS = 32;

    /** A full 25-bucket (or a partial one) trips this; well clear of ordinary forms' handful of fields. */
    private const MINING_THRESHOLD = 12;

    /** The honey-parameters to confirm + steer. In sqlmap's common-params.txt; closed list. */
    private const HONEY_KEYS = ['debug', 'cfg'];

    private function __construct()
    {
    }

    public static function detect(string $query): ?ParamIntent
    {
        $len = strlen($query);
        if ($len < 1 || $len > self::MAX_QUERY_BYTES) {
            return null;
        }

        $pairs = explode('&', $query);
        if (count($pairs) > self::MAX_PAIRS) {
            return null;
        }

        $canaryCount = 0;
        $honeyKey = null;
        $honeyValue = null;
        foreach ($pairs as $pair) {
            $eq = strpos($pair, '=');
            if ($eq === false) {
                continue;
            }
            // A canary is raw lowercase letters — no '+'/'%' to decode; a value carrying either cannot be
            // `^[a-z]{10}$`, so a byte-exact test needs no URL decode and can never widen the match.
            $value = substr($pair, $eq + 1);
            if (preg_match('/^[a-z]{10}$/', $value) !== 1) {
                continue;
            }
            $canaryCount++;
            if ($honeyKey === null) {
                $key = strtolower(substr($pair, 0, $eq));
                if (in_array($key, self::HONEY_KEYS, true)) {
                    $honeyKey = $key;
                    $honeyValue = $value;
                }
            }
        }

        if ($canaryCount < self::MINING_THRESHOLD || $honeyKey === null) {
            return null;
        }

        return ParamIntent::create(ParamIntent::KIND_DEBUG_CANARY, $honeyKey, (string) $honeyValue);
    }
}
