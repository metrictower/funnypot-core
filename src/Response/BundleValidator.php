<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * Checks that a candidate (body, headers) actually satisfies a bundle's compiled
 * constraints — the same checks nuclei will apply. Used to VALIDATE rich emulator
 * output before serving it; if an emulator's body fails, the composer falls back to
 * guaranteed-correct minimal synthesis, so richness can never break the scanner
 * guarantee.
 */
final class BundleValidator
{
    /**
     * @param array<string,mixed>  $bundle
     * @param array<string,string> $headers canonical-key => value
     */
    public static function satisfies(string $body, array $headers, array $bundle): bool
    {
        foreach (self::strings($bundle, 'bw') as $word) {
            if ($word !== '' && strpos($body, $word) === false) {
                return false;
            }
        }
        foreach (self::strings($bundle, 'nf') as $bad) {
            // nuclei checks negatives case-insensitively (dsl tolower / ci negative word).
            if ($bad !== '' && stripos($body, $bad) !== false) {
                return false;
            }
        }

        $block = self::headerBlock($headers);
        foreach (self::strings($bundle, 'hw') as $word) {
            if ($word !== '' && strpos($block, $word) === false) {
                return false;
            }
        }
        foreach (self::strings($bundle, 'hf') as $bad) {
            if ($bad !== '' && stripos($block, $bad) !== false) {
                return false;
            }
        }

        return self::headersSafe($headers);
    }

    /** No synthesized header name/value may carry CR, LF, or NUL (C8). */
    public static function headersSafe(array $headers): bool
    {
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n\x00]/', (string) $name) === 1 || preg_match('/[\r\n\x00]/', (string) $value) === 1) {
                return false;
            }
        }

        return true;
    }

    /**
     * nuclei's all_headers region: canonical "Key: value" lines, \n-joined, no status line.
     *
     * @param array<string,string> $headers
     */
    public static function headerBlock(array $headers): string
    {
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        return implode("\n", $lines);
    }

    /**
     * @param array<string,mixed> $bundle
     * @return string[]
     */
    private static function strings(array $bundle, string $key): array
    {
        return array_values(array_map('strval', (array) ($bundle[$key] ?? [])));
    }
}
