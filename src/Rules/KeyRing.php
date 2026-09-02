<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

use DateTimeImmutable;
use DateTimeInterface;
use DateTimeZone;

/**
 * The set of ed25519 public keys trusted to sign a rules release. Loaded from the vendored
 * resources/rules-signing-keys.php (the trust root — see that file), never from anything
 * fetched over the network. Only keys whose validity window covers the check time — AND whose
 * declared `roles` include the role being verified — are offered to the verifier, which is what
 * makes overlapping-window rotation and channel/release key separation work.
 *
 * FAIL-CLOSED normalisation: every entry is parsed once in the constructor. An entry is DROPPED
 * (never offered to the verifier) when its public key is malformed, or when a `valid_from` /
 * `valid_until` is present but unparseable — a typo in the trust root can only shrink trust, never
 * extend it. A `null` (or absent) window bound stays "unbounded" (the documented open-ended
 * rotation shape). An entry without a `roles` list matches NO role (fail-closed).
 */
final class KeyRing
{
    /** @var array<int,array{key_id:string,raw:string,from:?int,until:?int,roles:string[]}> */
    private $keys;

    /**
     * @param array<int,array<string,mixed>> $keys
     */
    public function __construct(array $keys)
    {
        $normalised = [];
        foreach ($keys as $key) {
            $raw = base64_decode((string) ($key['public_key'] ?? ''), true);
            if ($raw === false || strlen($raw) !== 32) {
                // Malformed / empty public key → drop the entry, never trust it.
                continue;
            }

            // A window bound present-but-unparseable fails closed: drop the whole key rather than
            // treat a corrupted date as "unbounded". null / absent means unbounded (open-ended).
            $from = null;
            if (array_key_exists('valid_from', $key) && $key['valid_from'] !== null) {
                $from = self::parseDate((string) $key['valid_from']);
                if ($from === null) {
                    continue;
                }
            }
            $until = null;
            if (array_key_exists('valid_until', $key) && $key['valid_until'] !== null) {
                $until = self::parseDate((string) $key['valid_until']);
                if ($until === null) {
                    continue;
                }
            }

            $roles = [];
            if (isset($key['roles']) && is_array($key['roles'])) {
                foreach ($key['roles'] as $role) {
                    if (is_string($role) && $role !== '') {
                        $roles[] = $role;
                    }
                }
            }

            $normalised[] = [
                'key_id' => (string) ($key['key_id'] ?? ''),
                'raw' => $raw,
                'from' => $from,
                'until' => $until,
                'roles' => $roles,
            ];
        }
        $this->keys = $normalised;
    }

    /** Load the ring bundled with the package. */
    public static function fromPackage(): self
    {
        $file = dirname(__DIR__, 2) . '/resources/rules-signing-keys.php';
        $data = is_file($file) ? require $file : ['keys' => []];

        return new self((array) ($data['keys'] ?? []));
    }

    public function isEmpty(): bool
    {
        return $this->keys === [];
    }

    /**
     * Raw 32-byte public keys valid at $at (defaults to now), newest window first. When $role is
     * non-null, only keys whose declared `roles` include it are returned (an entry with no `roles`
     * matches no role). When $role is null, the role filter is skipped (all active keys).
     *
     * @return array<int,array{key_id:string,raw:string}>
     */
    public function activeKeys(?int $at = null, ?string $role = null): array
    {
        $at = $at ?? time();
        $out = [];
        foreach ($this->keys as $key) {
            if ($key['from'] !== null && $at < $key['from']) {
                continue;
            }
            if ($key['until'] !== null && $at > $key['until']) {
                continue;
            }
            if ($role !== null && !in_array($role, $key['roles'], true)) {
                continue;
            }
            $out[] = ['key_id' => $key['key_id'], 'raw' => $key['raw']];
        }

        return $out;
    }

    /**
     * Strict date parse for a trust-root validity bound. Accepts a bare `Y-m-d` (pinned to midnight
     * UTC) or a full RFC3339 timestamp; anything else — a typo, an out-of-range field like
     * "2026-13-45", an empty string — returns null so the caller can fail closed. Deliberately NOT
     * `strtotime()`, whose leniency is exactly the fail-open bug being fixed.
     *
     * @return int|null unix timestamp, or null if unparseable
     */
    private static function parseDate(string $value): ?int
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }
        $utc = new DateTimeZone('UTC');
        foreach (['!Y-m-d', DateTimeInterface::RFC3339, 'Y-m-d\TH:i:s\Z'] as $format) {
            $dt = DateTimeImmutable::createFromFormat($format, $value, $utc);
            $errors = DateTimeImmutable::getLastErrors();
            $clean = $errors === false || (($errors['warning_count'] ?? 0) === 0 && ($errors['error_count'] ?? 0) === 0);
            if ($dt !== false && $clean) {
                return $dt->getTimestamp();
            }
        }

        return null;
    }
}
