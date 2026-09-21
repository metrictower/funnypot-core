<?php

declare(strict_types=1);

namespace Funnypot\Core\Support;

use Funnypot\Core\RequestContext;

/**
 * Closed input windows shared by core and its adapters.
 *
 * Request identity is admitted whole. Secondary inspection inputs are copied incrementally into
 * fixed windows before normalization, decoding or regular-expression work.
 */
final class BoundedInspection
{
    public const TARGET_BYTES = 4096;
    public const CANONICAL_HEADER_BYTES = 65536;
    public const CANONICAL_HEADER_FIELDS = 128;
    public const CANONICAL_HEADER_VALUES = 256;
    public const CANONICAL_VALUES_PER_FIELD = 16;
    public const HEADER_NAME_BYTES = 128;
    public const CANONICAL_HEADER_VALUE_BYTES = 8192;
    public const GENERIC_HEADER_BYTES = 16384;
    public const GENERIC_HEADER_FIELDS = 64;
    public const GENERIC_HEADER_VALUE_BYTES = 4096;
    public const HOST_BYTES = 512;
    public const BODY_BYTES = 32768;
    public const SUBJECT_BYTES = 32768;
    /** Retained for BC. Superseded by MAX_DECODE_DEPTH (FP-0356), which foldLayers uses instead. */
    public const DECODE_PASSES = 2;
    /**
     * FP-0356 recursive normalizer: max decode layers folded on top of raw before matching. Bounds
     * worst-case work with SUBJECT_BYTES. Every in-scope decoder is NON-EXPANDING (decoded layer is
     * never longer than its input — asserted in foldLayers), so total folded size stays <= a small
     * multiple of SUBJECT_BYTES regardless of decoder count and no decode-bomb is possible.
     */
    public const MAX_DECODE_DEPTH = 3;
    public const FINGERPRINT_BYTES = 4096;
    public const COOKIE_BYTES = 8192;
    public const COOKIE_PAIRS = 64;
    public const COOKIE_NAME_BYTES = 256;
    public const COOKIE_VALUE_BYTES = 4096;

    /** Saturates only on an impossible integer overflow; ordinary callers receive the exact count. */
    public static function targetBytes(string $path, string $query): int
    {
        $pathBytes = strlen($path);
        if ($query === '') {
            return $pathBytes;
        }

        $queryBytes = strlen($query);
        if ($pathBytes > PHP_INT_MAX - $queryBytes - 1) {
            return PHP_INT_MAX;
        }

        return $pathBytes + 1 + $queryBytes;
    }

    public static function rawTargetAccepted(string $target): bool
    {
        return strlen($target) <= self::TARGET_BYTES;
    }

    public static function targetComponentsAccepted(string $path, string $query): bool
    {
        return self::targetBytes($path, $query) <= self::TARGET_BYTES;
    }

    public static function targetAccepted(RequestContext $request): bool
    {
        return $request->targetAdmitted
            && self::targetComponentsAccepted($request->path, $request->query);
    }

    public static function host(string $host): string
    {
        return self::clip($host, self::HOST_BYTES);
    }

    /**
     * Build the plain-PHP canonical header snapshot without normalizing an overlong source name.
     *
     * @param array<mixed,mixed> $server
     * @return array<string,string>
     */
    public static function canonicalServerHeaders(array $server): array
    {
        return self::canonicalEntries(self::serverEntries($server));
    }

    /**
     * Build the PSR canonical header snapshot. Every source value is charged before conversion.
     *
     * @param array<mixed,mixed> $headers
     * @return array<string,string>
     */
    public static function canonicalPsrHeaders(array $headers): array
    {
        return self::canonicalEntries(self::psrEntries($headers));
    }

    /**
     * The smaller generic bot/attack projection, derived without touching more than 64 fields.
     *
     * @param array<mixed,mixed> $headers
     * @return array<string,string>
     */
    public static function genericHeaders(array $headers): array
    {
        $out = [];
        $case = [];
        $joined = [];
        $used = 0;
        $examined = 0;

        foreach ($headers as $rawName => $rawValue) {
            if ($examined >= self::GENERIC_HEADER_FIELDS) {
                break;
            }
            $examined++;

            $name = self::stringValue($rawName);
            if ($name === null || $name === '' || strlen($name) > self::HEADER_NAME_BYTES) {
                continue;
            }
            $value = self::stringValue($rawValue);
            if ($value === null) {
                continue;
            }
            $value = self::clip($value, self::GENERIC_HEADER_VALUE_BYTES);
            $lower = strtolower($name);

            if (isset($case[$lower])) {
                $keptName = $case[$lower];
                $separator = $joined[$lower] > 0 ? ', ' : '';
                $remaining = self::GENERIC_HEADER_BYTES - $used;
                if ($remaining < strlen($separator)) {
                    break;
                }
                $out[$keptName] .= $separator;
                $used += strlen($separator);
                $remaining = self::GENERIC_HEADER_BYTES - $used;
                $piece = self::clip($value, $remaining);
                $out[$keptName] .= $piece;
                $used += strlen($piece);
                $joined[$lower]++;
                if (strlen($piece) < strlen($value)) {
                    break;
                }
                continue;
            }

            $fixed = strlen($name) + 4; // ': ' + CRLF
            $remaining = self::GENERIC_HEADER_BYTES - $used;
            if ($remaining < $fixed) {
                break;
            }
            $piece = self::clip($value, $remaining - $fixed);
            $out[$name] = $piece;
            $case[$lower] = $name;
            $joined[$lower] = 1;
            $used += $fixed + strlen($piece);
            if (strlen($piece) < strlen($value)) {
                break;
            }
        }

        return $out;
    }

    /** @param array<mixed,mixed> $headers */
    public static function headerSurface(array $headers): string
    {
        $surface = '';
        $joined = 0;
        foreach (self::genericHeaders($headers) as $value) {
            self::append($surface, $joined > 0 ? ' ' : '', self::GENERIC_HEADER_BYTES);
            self::append($surface, $value, self::GENERIC_HEADER_BYTES);
            $joined++;
            if (strlen($surface) >= self::GENERIC_HEADER_BYTES) {
                break;
            }
        }

        return $surface;
    }

    /** @param array<mixed,mixed> $headers */
    public static function headerValue(array $headers, string $wanted): string
    {
        $wanted = self::clip($wanted, self::HEADER_NAME_BYTES);
        foreach (self::genericHeaders($headers) as $rawName => $value) {
            // An all-digit header name (a valid token) comes back as an int array key.
            $name = self::stringValue($rawName);
            if ($name !== null && strcasecmp($name, $wanted) === 0) {
                return $value;
            }
        }

        return '';
    }

    /**
     * Return the bounded Cookie header, or null when it is absent or exceeds its own window.
     *
     * @param array<mixed,mixed> $headers
     */
    public static function cookieHeader(array $headers): ?string
    {
        $examined = 0;
        foreach ($headers as $rawName => $rawValue) {
            if ($examined >= self::GENERIC_HEADER_FIELDS) {
                return null;
            }
            $examined++;
            $name = self::stringValue($rawName);
            if ($name === null || strlen($name) > self::HEADER_NAME_BYTES) {
                continue;
            }
            if (strcasecmp($name, 'Cookie') !== 0) {
                continue;
            }
            $value = self::stringValue($rawValue);
            if ($value === null || strlen($value) > self::COOKIE_BYTES) {
                return null;
            }

            return $value;
        }

        return null;
    }

    /**
     * Parse a bounded Cookie header without exploding the whole attacker string.
     * null means malformed or exhausted and is deliberately a fail-closed result.
     *
     * @return array<int,array{0:string,1:string}>|null
     */
    public static function cookiePairs(?string $header): ?array
    {
        if ($header === null || $header === '') {
            return [];
        }
        if (strlen($header) > self::COOKIE_BYTES) {
            return null;
        }

        $pairs = [];
        $offset = 0;
        $length = strlen($header);
        $examined = 0;
        while ($offset < $length) {
            if ($examined >= self::COOKIE_PAIRS) {
                return null;
            }
            $examined++;
            $separator = strpos($header, ';', $offset);
            $end = $separator === false ? $length : $separator;
            $segmentLength = $end - $offset;
            if ($segmentLength === 0 || trim(substr($header, $offset, $segmentLength)) === '') {
                $offset = $separator === false ? $length : $separator + 1;
                continue;
            }
            $equals = strpos($header, '=', $offset);
            if ($equals === false || $equals >= $end) {
                // A nameless (`=`-less) segment fails the whole header closed rather than guessing.
                return null;
            }

            $rawName = substr($header, $offset, $equals - $offset);
            $rawValue = substr($header, $equals + 1, $end - $equals - 1);
            if (strlen($rawName) > self::COOKIE_NAME_BYTES || strlen($rawValue) > self::COOKIE_VALUE_BYTES) {
                return null;
            }
            $name = trim($rawName);
            $value = trim($rawValue);
            if ($name === '') {
                return null;
            }
            $pairs[] = [$name, $value];
            $offset = $separator === false ? $length : $separator + 1;
        }

        return $pairs;
    }

    public static function requestSubject(RequestContext $request): string
    {
        if (!self::targetAccepted($request)) {
            return '';
        }

        return self::foldLayers(self::requestRaw($request));
    }

    /** The raw (undecoded) request surface: path + query + clipped body, under the byte cap. */
    private static function requestRaw(RequestContext $request): string
    {
        $raw = '';
        self::append($raw, $request->path, self::SUBJECT_BYTES);
        self::append($raw, ' ', self::SUBJECT_BYTES);
        self::append($raw, $request->query, self::SUBJECT_BYTES);
        self::append($raw, ' ', self::SUBJECT_BYTES);
        self::append($raw, self::clip((string) ($request->rawBody ?? ''), self::BODY_BYTES), self::SUBJECT_BYTES);

        return $raw;
    }

    /**
     * Bounded recursive decode/normalization (FP-0356). RETAINS the raw input and APPENDS each
     * decoded layer under the SUBJECT_BYTES cap, so decoding only ever ADDS a view a rule can match
     * — it never removes a match the raw would have caught. Peels the common evasion encodings
     * (percent, '+', \uXXXX, HTML-entity, plausible base64, prefixed/long hex, nested-JSON string
     * values) toward a fixed point, one decoder per pass, bounded by MAX_DECODE_DEPTH and the byte
     * cap. INVARIANT: every decoder is non-expanding (a decoded layer is never longer than its
     * input), enforced below — so total folded size stays within a small multiple of SUBJECT_BYTES
     * and no decode-bomb (base64-of-base64, entity expansion) is possible.
     *
     * @param string[]|null $applied out: ordered, de-duplicated names of the decoders that fired
     *                               (the decode_path telemetry; applied-set, not a winning chain).
     */
    public static function foldLayers(string $raw, ?array &$applied = null): string
    {
        if ($applied === null) {
            $applied = [];
        }
        // Clamp the input so the invariant (output <= SUBJECT_BYTES) holds even for a caller that
        // passes an un-clipped raw; the built-in callers already clip, this is belt-and-braces.
        $raw = self::clip($raw, self::SUBJECT_BYTES);
        $subject = $raw;
        $layer = $raw;
        for ($depth = 0; $depth < self::MAX_DECODE_DEPTH; $depth++) {
            if (strlen($subject) >= self::SUBJECT_BYTES) {
                break;
            }
            $usedName = null;
            foreach (self::DECODER_ORDER as $name) {
                $decoded = self::decodeLayer($name, $layer);
                if ($decoded === null || $decoded === '' || $decoded === $layer) {
                    continue;
                }
                // Non-expanding invariant (bomb guard): reject any decoder that GREW the layer, so a
                // future expanding decoder (e.g. utf7) cannot turn the fold into an expansion bomb.
                if (strlen($decoded) > strlen($layer)) {
                    continue;
                }
                $usedName = $name;
                $layer = $decoded;
                break;
            }
            if ($usedName === null) {
                break;
            }
            self::append($subject, ' ', self::SUBJECT_BYTES);
            self::append($subject, $layer, self::SUBJECT_BYTES);
            if (!in_array($usedName, $applied, true)) {
                $applied[] = $usedName;
            }
        }

        return $subject;
    }

    /**
     * The decoders that transformed this request's surface (FP-0356 decode_path). Applied-set, not a
     * winning chain: the ordered, de-duplicated decoders that produced a new layer when folding the
     * request surface (path + query + body). Telemetry only — surfaced additively on the Verdict.
     *
     * @return string[]
     */
    public static function appliedDecoders(RequestContext $request): array
    {
        if (!self::targetAccepted($request)) {
            return [];
        }
        $applied = [];
        self::foldLayers(self::requestRaw($request), $applied);

        return $applied;
    }

    /**
     * Decode chain order. base64 is tried BEFORE plus so a base64 token containing '+' is decoded
     * whole, rather than the '+' first being rewritten to a space (which would break the token).
     */
    private const DECODER_ORDER = ['percent', 'base64', 'plus', 'unicode', 'entity', 'hex', 'json'];

    /** One bounded decode step; null when the decoder does not apply to this layer. */
    private static function decodeLayer(string $name, string $layer): ?string
    {
        switch ($name) {
            case 'percent':
                return self::hasPercentOctet($layer) ? rawurldecode($layer) : null;
            case 'plus':
                return strpos($layer, '+') === false ? null : str_replace('+', ' ', $layer);
            case 'unicode':
                return self::decodeUnicodeEscapes($layer);
            case 'entity':
                return strpos($layer, '&') === false ? null : self::decodeHtmlEntities($layer);
            case 'base64':
                return self::decodePlausibleBase64($layer);
            case 'hex':
                return self::decodeHex($layer);
            case 'json':
                return self::decodeJsonStrings($layer);
        }

        return null;
    }

    /**
     * Unicode escapes -> the BMP character (no mbstring; manual UTF-8 encode). Handles both the JS
     * `\uXXXX` form and the IIS/`%uXXXX` form (a distinct evasion vector percent-decode leaves alone,
     * since `%u` is not a valid percent-octet).
     */
    private static function decodeUnicodeEscapes(string $value): ?string
    {
        if (strpos($value, '\\u') === false && stripos($value, '%u') === false) {
            return null;
        }
        $out = preg_replace_callback('/(?:\\\\u|%u)([0-9a-fA-F]{4})/i', static function (array $m): string {
            return self::codepointToUtf8((int) hexdec($m[1]));
        }, $value);

        return ($out === null || $out === $value) ? null : $out;
    }

    /** Encode a BMP codepoint as UTF-8 (\uXXXX is 4 hex, so at most 3 bytes). */
    private static function codepointToUtf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }

        return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    /**
     * HTML entities (&lt; &#65; &amp; …) -> their characters. Never expands. NOTE: this decodes any
     * escaped markup, so a benign body that legitimately escapes an attack token (e.g. `&amp;lt;script&amp;gt;`
     * in prose) folds to the literal token — but only a would-be-404 path reaches the attack scan
     * (classifyContent route-gates real routes to CLEAN first), and raw is retained, so this widens
     * recall without new false negatives.
     */
    private static function decodeHtmlEntities(string $value): ?string
    {
        $out = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        return $out === $value ? null : $out;
    }

    /**
     * Plausible base64 tokens -> their decoded bytes. Gated to AVOID false positives: only a run of
     * >=16 base64 chars whose length is a multiple of 4, that strict-decodes to MOSTLY-PRINTABLE
     * text, is decoded — so a random alphanumeric id/hash/cookie is left alone.
     */
    private static function decodePlausibleBase64(string $value): ?string
    {
        if (!preg_match('#[A-Za-z0-9+/]{16,}={0,2}#', $value)) {
            return null;
        }
        $changed = false;
        $out = preg_replace_callback('#[A-Za-z0-9+/]{16,}={0,2}#', static function (array $m) use (&$changed): string {
            $tok = $m[0];
            if (strlen($tok) % 4 !== 0) {
                return $tok;
            }
            $decoded = base64_decode($tok, true);
            if ($decoded === false || $decoded === '' || !self::mostlyPrintable($decoded)) {
                return $tok;
            }
            $changed = true;

            return $decoded;
        }, $value);

        return ($changed && $out !== null && $out !== $value) ? $out : null;
    }

    /**
     * Hex-encoded bytes -> characters. Short runs MUST carry a `\x` or `0x` prefix (so a 6-hex CSS
     * colour like `a1b2c3` is never decoded); a long BARE run (>=16, even length) is decoded only
     * when it yields mostly-printable text (so a hash/digest, which decodes to binary, is skipped).
     */
    private static function decodeHex(string $value): ?string
    {
        $changed = false;
        $out = preg_replace_callback('/(?:\\\\x|0x)([0-9a-fA-F]{2})/', static function (array $m) use (&$changed): string {
            $changed = true;

            return chr((int) hexdec($m[1]));
        }, $value);
        if ($out === null) {
            $out = $value;
        }
        $out = preg_replace_callback('/\b[0-9a-fA-F]{16,}\b/', static function (array $m) use (&$changed): string {
            $tok = $m[0];
            if (strlen($tok) % 2 !== 0) {
                return $tok;
            }
            $decoded = @hex2bin($tok);
            if ($decoded === false || !self::mostlyPrintable($decoded)) {
                return $tok;
            }
            $changed = true;

            return $decoded;
        }, $out);

        return ($changed && $out !== null && $out !== $value) ? $out : null;
    }

    /** Nested-JSON string values, concatenated -> exposes a payload hidden in a JSON body. */
    private static function decodeJsonStrings(string $value): ?string
    {
        $trimmed = ltrim($value);
        if ($trimmed === '' || ($trimmed[0] !== '{' && $trimmed[0] !== '[')) {
            return null;
        }
        $data = json_decode($value, true);
        if (!is_array($data)) {
            return null;
        }
        $strings = [];
        self::collectJsonStrings($data, $strings, 0);
        if ($strings === []) {
            return null;
        }
        $joined = implode(' ', $strings);

        // Non-expanding: extracted string values are a subset of the JSON source bytes.
        return ($joined !== $value && strlen($joined) <= strlen($value)) ? $joined : null;
    }

    /**
     * @param mixed    $node
     * @param string[] $out
     */
    private static function collectJsonStrings($node, array &$out, int $depth): void
    {
        if ($depth > self::MAX_DECODE_DEPTH || count($out) > 256) {
            return;
        }
        foreach ((array) $node as $value) {
            if (is_string($value)) {
                $out[] = $value;
            } elseif (is_array($value)) {
                self::collectJsonStrings($value, $out, $depth + 1);
            }
        }
    }

    /** True when >=85% of the bytes are printable ASCII/whitespace — the base64/hex plausibility gate. */
    private static function mostlyPrintable(string $s): bool
    {
        $len = strlen($s);
        if ($len === 0) {
            return false;
        }
        $printable = 0;
        for ($i = 0; $i < $len; $i++) {
            $c = ord($s[$i]);
            if ($c === 9 || $c === 10 || $c === 13 || ($c >= 32 && $c < 127)) {
                $printable++;
            }
        }

        return $printable / $len >= 0.85;
    }

    /** One bounded decode for capture-specific normalizers outside the generic request builder. */
    public static function decodeOnce(string $value): string
    {
        return rawurldecode(self::clip($value, self::SUBJECT_BYTES));
    }

    /**
     * Preserve the attack emulator's selector vocabulary behind one bounded implementation.
     *
     * @param array<int|string,string> $captures
     */
    public static function surface(RequestContext $request, string $in, array $captures = []): string
    {
        if (strncmp($in, 'header:', 7) === 0) {
            return self::headerValue($request->headers, substr($in, 7));
        }
        if (strncmp($in, 'match.', 6) === 0) {
            $ref = substr($in, 6);
            $key = is_numeric($ref) ? (int) $ref : $ref;

            return self::clip((string) ($captures[$key] ?? ''), self::SUBJECT_BYTES);
        }

        switch ($in) {
            case 'header':
            case 'headers':
                return self::headerSurface($request->headers);
            case 'path':
                // Path stays raw: it is structural (routing already normalizes it) and folding it
                // adds false-positive surface for no evasion win.
                return self::clip($request->path, self::SUBJECT_BYTES);
            case 'query':
                // FP-0356: fold the query arm so query-pinned rules (xss/open-redirect) catch encoded
                // evasions, matching what the `request` arm already does for the concatenated surface.
                return self::foldLayers(self::clip($request->query, self::SUBJECT_BYTES));
            case 'method':
                return self::clip($request->method, self::SUBJECT_BYTES);
            case 'body':
                // FP-0356: fold the body arm too (body-pinned rules: xxe, sqli in POST bodies).
                return self::foldLayers(self::clip((string) ($request->rawBody ?? ''), self::BODY_BYTES));
            case 'request':
            default:
                return self::requestSubject($request);
        }
    }

    private static function hasPercentOctet(string $value): bool
    {
        $length = strlen($value);
        for ($i = 0; $i + 2 < $length; $i++) {
            if ($value[$i] === '%' && strspn($value, '0123456789abcdefABCDEF', $i + 1, 2) === 2) {
                return true;
            }
        }

        return false;
    }

    private static function append(string &$target, string $value, int $cap): void
    {
        $remaining = $cap - strlen($target);
        if ($remaining <= 0 || $value === '') {
            return;
        }
        $target .= self::clip($value, $remaining);
    }

    private static function clip(string $value, int $cap): string
    {
        return strlen($value) > $cap ? substr($value, 0, $cap) : $value;
    }

    /** @return string|null */
    private static function stringValue($value): ?string
    {
        if (is_string($value)) {
            return $value;
        }
        if (is_scalar($value) || (is_object($value) && method_exists($value, '__toString'))) {
            try {
                return (string) $value;
            } catch (\Throwable $e) {
                return null;
            }
        }

        return null;
    }

    /**
     * @param \Generator<int,array{0:mixed,1:array<mixed>}> $entries
     * @return array<string,string>
     */
    private static function canonicalEntries(\Generator $entries): array
    {
        $out = [];
        $case = [];
        $joined = [];
        $used = 0;
        $fields = 0;
        $valuesTotal = 0;

        $entries->rewind();
        while ($entries->valid()) {
            $entry = $entries->current();
            $fields++;
            $name = self::stringValue($entry[0]);
            $validName = $name !== null && $name !== '' && strlen($name) <= self::HEADER_NAME_BYTES;
            $lower = $validName ? strtolower($name) : '';
            $values = $entry[1];

            if ($validName && !isset($case[$lower])) {
                $fixed = strlen($name) + 4;
                $remaining = self::CANONICAL_HEADER_BYTES - $used;
                if ($remaining < $fixed) {
                    break;
                }
                $out[$name] = '';
                $case[$lower] = $name;
                $joined[$lower] = 0;
                $used += $fixed;
            }

            $perField = 0;
            foreach ($values as $rawValue) {
                if ($perField >= self::CANONICAL_VALUES_PER_FIELD || $valuesTotal >= self::CANONICAL_HEADER_VALUES) {
                    break;
                }
                $perField++;
                $valuesTotal++;
                if (!$validName) {
                    continue;
                }
                $value = self::stringValue($rawValue);
                if ($value === null) {
                    continue;
                }
                $value = self::clip($value, self::CANONICAL_HEADER_VALUE_BYTES);
                $keptName = $case[$lower];
                $separator = $joined[$lower] > 0 ? ', ' : '';
                $remaining = self::CANONICAL_HEADER_BYTES - $used;
                if ($remaining < strlen($separator)) {
                    break 2;
                }
                $out[$keptName] .= $separator;
                $used += strlen($separator);
                $remaining = self::CANONICAL_HEADER_BYTES - $used;
                $piece = self::clip($value, $remaining);
                $out[$keptName] .= $piece;
                $used += strlen($piece);
                $joined[$lower]++;
                if (strlen($piece) < strlen($value)) {
                    break 2;
                }
            }

            if ($fields >= self::CANONICAL_HEADER_FIELDS || $valuesTotal >= self::CANONICAL_HEADER_VALUES) {
                break;
            }
            $entries->next();
        }

        return $out;
    }

    /**
     * Laziness is load-bearing: canonicalEntries stops advancing this source as soon as either the
     * field or value budget is spent.
     *
     * @param array<mixed,mixed> $headers
     * @return \Generator<int,array{0:mixed,1:array<mixed>}>
     */
    private static function psrEntries(array $headers): \Generator
    {
        foreach ($headers as $name => $values) {
            yield [$name, is_array($values) ? $values : [$values]];
        }
    }

    /**
     * @param array<mixed,mixed> $server
     * @return \Generator<int,array{0:mixed,1:array<mixed>}>
     */
    private static function serverEntries(array $server): \Generator
    {
        $overlongName = null;
        foreach ($server as $key => $value) {
            if (!is_string($key) || strncmp($key, 'HTTP_', 5) !== 0) {
                continue;
            }
            if (strlen($key) > 5 + self::HEADER_NAME_BYTES) {
                if ($overlongName === null) {
                    $overlongName = str_repeat('x', self::HEADER_NAME_BYTES + 1);
                }
                yield [$overlongName, [$value]];
                continue;
            }
            $rawName = substr($key, 5);
            $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', $rawName))));
            yield [$name, [$value]];
        }
    }
}
