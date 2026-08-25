<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * Request-shape bot signals computed by classify() (decision S / two-phase design §2.4).
 *
 * Pure data: named boolean flags for each fired signal, the accumulated anomaly weight,
 * a coarse UA class, and a digit-stripped structural header fingerprint. It rides on the
 * Verdict so the policy can read it (composite bot decision) and forward it as telemetry.
 *
 * INPUT-side only. None of the flag names, the weight, or the fingerprint are ever emitted
 * in a response — an attacker must not be able to read the honeypot's own detection logic
 * back off the wire (project invariant #1).
 *
 * NAVIGATION vs SUBRESOURCE. `sec-fetch-mode` is read for its VALUE, not merely its presence:
 * a browser sends a different header set for a page load than for the fetch/XHR calls that page
 * makes. MISSING_ACCEPT_LANGUAGE, MISSING_ACCEPT_ENCODING and ACCEPT_WILDCARD_FROM_BROWSER are
 * therefore scored on navigations ONLY — on a subresource those headers are irrelevant rather
 * than weak evidence, and charging them made every AJAX call on a JS-heavy site anomalous.
 * An unknown request shape is treated as a navigation, so nothing is suppressed without positive
 * evidence. A client claiming `sec-fetch-mode: cors` gains at most those three signals and cannot
 * suppress the scanner-UA, empty-UA, client-hint-contradiction, platform-mismatch or h2 signals.
 *
 * 7.3-clean: classic constructor, docblocked untyped properties (no promotion / typed props).
 */
final class BotSignalSet
{
    /** Coarse UA classes. */
    public const UA_BROWSER = 'browser';
    public const UA_SCRIPT = 'script';
    public const UA_SCANNER = 'scanner';
    public const UA_EMPTY = 'empty';
    public const UA_UNKNOWN = 'unknown';

    /** Signal flag names (generic HTTP-header vocabulary — never a scanner/matcher signature). */
    public const MISSING_ACCEPT = 'missing_accept';
    public const MISSING_ACCEPT_LANGUAGE = 'missing_accept_language';
    public const MISSING_ACCEPT_ENCODING = 'missing_accept_encoding';
    public const EMPTY_USER_AGENT = 'empty_user_agent';
    public const MISSING_FETCH_METADATA = 'missing_fetch_metadata';
    public const MISSING_CLIENT_HINTS = 'missing_client_hints';
    public const UA_CLAIMS_BROWSER_NO_HINTS = 'ua_claims_browser_no_hints';
    public const ACCEPT_WILDCARD_FROM_BROWSER = 'accept_wildcard_from_browser';
    public const H2_FORBIDDEN_CONNECTION = 'h2_forbidden_connection';
    public const ACCEPT_ENCODING_NO_GZIP = 'accept_encoding_no_gzip';
    public const UA_PLATFORM_MISMATCH = 'ua_platform_mismatch';
    public const SCANNER_USER_AGENT = 'scanner_user_agent';

    /** @var array<string,bool> named boolean flags for each fired signal */
    public $flags;

    /** @var int accumulated anomaly weight */
    public $weight;

    /** @var string coarse UA class (one of the UA_* constants) */
    public $uaClass;

    /** @var string digit-stripped, sorted-list structural header fingerprint */
    public $fingerprint;

    /**
     * @param array<string,bool> $flags
     */
    public function __construct(
        array $flags = [],
        int $weight = 0,
        string $uaClass = self::UA_UNKNOWN,
        string $fingerprint = ''
    ) {
        $this->flags = $flags;
        $this->weight = $weight;
        $this->uaClass = $uaClass;
        $this->fingerprint = $fingerprint;
    }

    /** A signal set with nothing fired — the clean default. */
    public static function empty(): self
    {
        return new self([], 0, self::UA_UNKNOWN, '');
    }

    /** True when at least one signal flag fired. */
    public function anyFired(): bool
    {
        foreach ($this->flags as $on) {
            if ($on === true) {
                return true;
            }
        }

        return false;
    }

    /** True when the named signal flag is set. */
    public function has(string $flag): bool
    {
        return isset($this->flags[$flag]) && $this->flags[$flag] === true;
    }

    /**
     * Pure-data projection — so the set can cross the policy boundary, be cached/logged,
     * or become the opt-in `signals` telemetry payload (decision T).
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'flags' => $this->flags,
            'weight' => $this->weight,
            'uaClass' => $this->uaClass,
            'fingerprint' => $this->fingerprint,
        ];
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $flags = [];
        foreach ((array) ($data['flags'] ?? []) as $name => $on) {
            $flags[(string) $name] = $on === true;
        }

        return new self(
            $flags,
            (int) ($data['weight'] ?? 0),
            (string) ($data['uaClass'] ?? self::UA_UNKNOWN),
            (string) ($data['fingerprint'] ?? '')
        );
    }
}
