<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

/**
 * The strict, closed query-parameter intent classifier. A PURE function of the raw query string
 * (RequestContext::$query — the bytes after `?`); it performs no I/O, reads no superglobal, and never
 * uses PHP `parse_str()` (whose variable/array coercions turn `a[b]=1` into a nested map) or
 * `urldecode()`/`rawurldecode()` (which tolerate malformed escapes).
 *
 * Bounds, in order, ALL enforced before a value is trusted:
 *  - raw query is 1..2048 bytes;
 *  - at most 32 `&`-separated pairs (a 33rd rejects the whole query); `;` is data, not a separator;
 *  - each pair splits at its FIRST literal `=`; a missing `=` yields an empty value that matches nothing;
 *  - `+` is a space and every `%` introduces exactly one `%HH` octet, decoded ONCE (so `%252e` yields
 *    the literal `%2e`, never a re-decoded `.`); a malformed escape anywhere rejects the whole query;
 *  - a recognized value rejects NUL/C0/DEL/C1 and invalid UTF-8, and is 1..256 decoded bytes;
 *  - a key matches /^[a-z][a-z0-9_-]{0,31}$/i (so `q[]` and empty keys fail) and is lower-cased;
 *  - a duplicate of any recognized canonical key (case-insensitive) invalidates the whole query.
 *
 * The fixed priority table (file-read > redirect-notice > debug-view > command-result > search-result)
 * decides the kind regardless of pair order. The result carries only the canonical kind/key/value —
 * never the raw query, unknown pairs, order, host, path, headers or body.
 *
 * 7.3-safe: strpos/substr/explode/preg_* only; no mb_*, no str_contains/str_starts_with/match.
 */
final class QueryIntentClassifier
{
    private const MAX_QUERY_BYTES = 2048;
    private const MAX_PAIRS = 32;

    /** Every recognized canonical key => true, for the fast "is this one of ours" test. */
    private const RECOGNIZED = [
        'file' => true, 'path' => true, 'page' => true,
        'url' => true, 'host' => true, 'redirect' => true, 'next' => true, 'ref' => true, 'route' => true,
        'debug' => true,
        'cmd' => true,
        'q' => true, 'search' => true, 'msg' => true, 'note' => true,
    ];

    /** The closed familiar file names a bare (slash-free) file-read value may equal or end with. */
    private const FAMILIAR_FILES = ['.env', 'passwd', 'shadow', 'hosts', 'wp-config.php', 'web.config', '.htaccess'];

    /** Exact debug tokens (compared case-insensitively) that turn `debug` into a debug-view intent. */
    private const DEBUG_TOKENS = ['1', 'true', 'on', 'yes'];

    private function __construct()
    {
    }

    public static function classify(string $query): ?ParamIntent
    {
        $len = strlen($query);
        if ($len < 1 || $len > self::MAX_QUERY_BYTES) {
            return null;
        }

        $pairs = explode('&', $query);
        if (count($pairs) > self::MAX_PAIRS) {
            return null;
        }

        /** @var array<string,string> $recognized canonical key => decoded value */
        $recognized = [];
        foreach ($pairs as $pair) {
            $eq = strpos($pair, '=');
            if ($eq === false) {
                // A key-only probe has no value and can match nothing; it still counts toward the
                // 32-pair bound (already counted by explode()).
                continue;
            }

            $rawKey = substr($pair, 0, $eq);
            $key = self::decodeOnce($rawKey);
            if ($key === null) {
                return null; // a malformed escape anywhere => the whole query is malformed => no intent
            }
            if (preg_match('/^[a-z][a-z0-9_-]{0,31}$/i', $key) !== 1) {
                continue; // not a canonical-shaped key (brackets, empty, over-long) => ignore this pair
            }
            $canon = strtolower($key);
            if (!isset(self::RECOGNIZED[$canon])) {
                continue; // unknown key => ignore (still counted toward the bound)
            }

            $value = self::decodeOnce(substr($pair, $eq + 1));
            if ($value === null) {
                return null;
            }
            if (!self::valueIsClean($value)) {
                return null; // control/invalid-UTF-8/oversized on a recognized key => no intent
            }
            if (isset($recognized[$canon])) {
                return null; // duplicate recognized key (case-insensitive) => no intent
            }
            $recognized[$canon] = $value;
        }

        return self::selectByPriority($recognized);
    }

    /**
     * `+` => space, then a single anchored `%HH` decode. The pre-check rejects any `%` NOT followed by
     * two hex digits (so `%`, `%2`, `%zz` fail); preg_replace_callback then replaces each `%HH` exactly
     * once and does not re-scan its own output, so `%25` becomes a literal `%` and `%252e` becomes the
     * literal `%2e`. Null on a malformed escape.
     */
    private static function decodeOnce(string $s): ?string
    {
        $s = str_replace('+', ' ', $s);
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $s) === 1) {
            return null;
        }

        $decoded = preg_replace_callback('/%([0-9A-Fa-f]{2})/', static function (array $m): string {
            return chr((int) hexdec($m[1]));
        }, $s);

        return $decoded === null ? null : $decoded;
    }

    /** A recognized value must be 1..256 bytes, control-free and valid UTF-8 (same bounds as ParamIntent). */
    private static function valueIsClean(string $value): bool
    {
        $len = strlen($value);
        if ($len < 1 || $len > ParamIntent::MAX_VALUE_BYTES) {
            return false;
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $value) === 1) {
            return false;
        }
        if (preg_match('/\xc2[\x80-\x9f]/', $value) === 1) {
            return false;
        }

        return preg_match('//u', $value) === 1;
    }

    /**
     * The fixed cross-kind priority. The first kind (in table order) with a present key whose value
     * matches that kind's shape wins, regardless of pair order.
     *
     * @param array<string,string> $recognized
     */
    private static function selectByPriority(array $recognized): ?ParamIntent
    {
        // 1. file-read — a path-like value only (page=2 is ordinary and matches nothing).
        foreach (ParamIntent::keysForKind(ParamIntent::KIND_FILE_READ) as $key) {
            if (isset($recognized[$key]) && self::isPathLike($recognized[$key])) {
                return ParamIntent::create(ParamIntent::KIND_FILE_READ, $key, $recognized[$key]);
            }
        }
        // 2. redirect-notice — any non-empty value (display-only; never a destination).
        foreach (ParamIntent::keysForKind(ParamIntent::KIND_REDIRECT_NOTICE) as $key) {
            if (isset($recognized[$key])) {
                return ParamIntent::create(ParamIntent::KIND_REDIRECT_NOTICE, $key, $recognized[$key]);
            }
        }
        // 3. debug-view — an exact on-token only.
        if (isset($recognized['debug']) && in_array(strtolower($recognized['debug']), self::DEBUG_TOKENS, true)) {
            return ParamIntent::create(ParamIntent::KIND_DEBUG_VIEW, 'debug', $recognized['debug']);
        }
        // 4. command-result — any non-empty value.
        if (isset($recognized['cmd'])) {
            return ParamIntent::create(ParamIntent::KIND_COMMAND_RESULT, 'cmd', $recognized['cmd']);
        }
        // 5. search-result — any non-empty value.
        foreach (ParamIntent::keysForKind(ParamIntent::KIND_SEARCH_RESULT) as $key) {
            if (isset($recognized[$key])) {
                return ParamIntent::create(ParamIntent::KIND_SEARCH_RESULT, $key, $recognized[$key]);
            }
        }

        return null;
    }

    /**
     * Path-like: contains a separator or traversal marker, or equals/ends with a closed familiar name.
     * A bare ordinary token (`page=2`, `q=cats`) is NOT path-like.
     */
    private static function isPathLike(string $value): bool
    {
        if (strpos($value, '/') !== false || strpos($value, '\\') !== false || strpos($value, '..') !== false) {
            return true;
        }
        $lower = strtolower($value);
        foreach (self::FAMILIAR_FILES as $name) {
            $nameLen = strlen($name);
            if ($lower === $name || ($nameLen < strlen($lower) && substr($lower, -$nameLen) === $name)) {
                return true;
            }
        }

        return false;
    }
}
