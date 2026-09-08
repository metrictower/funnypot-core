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
    public const DECODE_PASSES = 2;
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

        $raw = '';
        self::append($raw, $request->path, self::SUBJECT_BYTES);
        self::append($raw, ' ', self::SUBJECT_BYTES);
        self::append($raw, $request->query, self::SUBJECT_BYTES);
        self::append($raw, ' ', self::SUBJECT_BYTES);
        self::append($raw, self::clip((string) ($request->rawBody ?? ''), self::BODY_BYTES), self::SUBJECT_BYTES);

        $subject = $raw;
        $layer = $raw;
        for ($pass = 0; $pass < self::DECODE_PASSES; $pass++) {
            if (!self::hasPercentOctet($layer) || strlen($subject) >= self::SUBJECT_BYTES) {
                // Deliberate: percent-free input has no decode layer to append, so the subject is raw alone.
                break;
            }
            $decoded = rawurldecode($layer);
            if ($decoded === $layer) {
                break;
            }
            self::append($subject, ' ', self::SUBJECT_BYTES);
            self::append($subject, $decoded, self::SUBJECT_BYTES);
            $layer = $decoded;
        }

        return $subject;
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
                return self::clip($request->path, self::SUBJECT_BYTES);
            case 'query':
                return self::clip($request->query, self::SUBJECT_BYTES);
            case 'method':
                return self::clip($request->method, self::SUBJECT_BYTES);
            case 'body':
                return self::clip((string) ($request->rawBody ?? ''), self::BODY_BYTES);
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
