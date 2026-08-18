<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * Shared helpers for endpoint emulators: matcher-token access, deterministic fake
 * values, the taunt banner, and a guarantee that every required token ends up in the
 * body. Concrete emulators build believable content and lean on appendMissingTokens()
 * so they can never accidentally drop a matcher word.
 */
abstract class AbstractEmulator implements EndpointEmulator
{
    /**
     * Match a bundle by template-id needle (substring) or exact product id.
     *
     * @param array<string,mixed> $bundle
     * @param string[]            $needles
     */
    protected function matches(array $bundle, array $needles): bool
    {
        $pid = (string) ($bundle['pid'] ?? '');
        foreach ($needles as $needle) {
            if ($pid === $needle) {
                return true;
            }
            foreach ((array) ($bundle['t'] ?? []) as $id) {
                if (strpos((string) $id, $needle) !== false) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @param array<string,mixed> $bundle
     * @return string[]
     */
    protected function required(array $bundle): array
    {
        return array_values(array_map('strval', (array) ($bundle['bw'] ?? [])));
    }

    /**
     * Deterministic hex token of $len chars from the seed (obviously-fake filler for
     * keys/hashes/nonces). Stable per attacker+path so re-scans are byte-identical.
     */
    protected function fakeHex(int $seed, string $salt, int $len): string
    {
        return substr(hash('sha256', $seed . '|' . $salt), 0, max(1, $len));
    }

    /**
     * Deterministic pick from a list.
     *
     * @param array<int,string> $options
     */
    protected function pick(array $options, int $seed, string $salt): string
    {
        if ($options === []) {
            return '';
        }

        return $options[crc32($seed . '|' . $salt) % count($options)];
    }

    /**
     * Append any required token not already present, one per line, so the body always
     * satisfies the matcher no matter how the rich content came out.
     *
     * @param array<string,mixed> $bundle
     */
    protected function appendMissingTokens(string $body, array $bundle): string
    {
        foreach ($this->required($bundle) as $word) {
            if ($word !== '' && strpos($body, $word) === false) {
                $body .= "\n" . $word;
            }
        }

        return $body;
    }

    /**
     * "Nice try" banner in the file's comment syntax. Plain text only — never contains
     * markup that could trip a forbidden substring; the composer validates regardless.
     */
    protected function tauntBanner(string $open, string $close = ''): string
    {
        $lines = [
            'nice try.',
            'this endpoint is a honeypot. nothing here is real.',
            'your scan has been logged.',
        ];
        $out = [];
        foreach ($lines as $line) {
            $out[] = $close === '' ? ($open . ' ' . $line) : ($open . ' ' . $line . ' ' . $close);
        }

        return implode("\n", $out);
    }
}
