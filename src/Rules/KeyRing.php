<?php

declare(strict_types=1);

namespace Funnypot\Rules;

/**
 * The set of ed25519 public keys trusted to sign a rules release. Loaded from the vendored
 * resources/rules-signing-keys.php (the trust root — see that file), never from anything
 * fetched over the network. Only keys whose validity window covers the check time are
 * offered to the verifier, which is what makes overlapping-window rotation work.
 */
final class KeyRing
{
    /** @var array<int,array{key_id:string,public_key:string,valid_from:?string,valid_until:?string}> */
    private $keys;

    /**
     * @param array<int,array<string,mixed>> $keys
     */
    public function __construct(array $keys)
    {
        $normalised = [];
        foreach ($keys as $key) {
            $pub = (string) ($key['public_key'] ?? '');
            if ($pub === '') {
                continue;
            }
            $normalised[] = [
                'key_id' => (string) ($key['key_id'] ?? ''),
                'public_key' => $pub,
                'valid_from' => isset($key['valid_from']) ? (string) $key['valid_from'] : null,
                'valid_until' => isset($key['valid_until']) && $key['valid_until'] !== null
                    ? (string) $key['valid_until']
                    : null,
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
     * Raw 32-byte public keys valid at $at (defaults to now), newest window first. An entry
     * with an unparseable or malformed base64 key is skipped rather than trusted.
     *
     * @return array<int,array{key_id:string,raw:string}>
     */
    public function activeKeys(?int $at = null): array
    {
        $at = $at ?? time();
        $out = [];
        foreach ($this->keys as $key) {
            if ($key['valid_from'] !== null) {
                $from = strtotime($key['valid_from']);
                if ($from !== false && $at < $from) {
                    continue;
                }
            }
            if ($key['valid_until'] !== null) {
                $until = strtotime($key['valid_until']);
                if ($until !== false && $at > $until) {
                    continue;
                }
            }
            $raw = base64_decode($key['public_key'], true);
            if ($raw === false || strlen($raw) !== 32) {
                continue;
            }
            $out[] = ['key_id' => $key['key_id'], 'raw' => $raw];
        }

        return $out;
    }
}
