<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Crs;

use RuntimeException;

/**
 * Fingerprint-safety gate. Scans response text (body + header values) for any signature an
 * upstream detection source uses to identify itself — CRS's `OWASP_CRS`/`paranoia-level`
 * tags, a bare CRS rule id, `ModSecurity`/`libinjection` mentions, etc. A hit is a leak of
 * the DETECTOR into what funnypot serves, which lets an attacker classify the reply as canned.
 *
 * This backs both the compile-time lint (CrsCompiler::assertResponseClean, mirroring
 * EmulatorCompiler's own "compiles but silently wrong = build failure" screens) and the CI
 * script scripts/ci/check-fingerprint-safety.php, so one denylist governs every path.
 */
final class FingerprintGuard
{
    /** @var string[] */
    private $literals;

    /** @var string[] */
    private $patterns;

    /**
     * @param string[] $literals case-insensitive substrings that must not appear
     * @param string[] $patterns regex signatures (no delimiters) that must not match
     */
    public function __construct(array $literals, array $patterns)
    {
        $this->literals = $literals;
        $this->patterns = $patterns;
    }

    /**
     * Load the tracked, append-only denylist bundled with the package. A missing file, or a
     * present-but-degenerate denylist (empty literals AND patterns — e.g. a resource truncated to
     * no `return`, or edited to `return []`), throws rather than silently building a no-op guard
     * that would pass every response as clean: a caller relying on this to verify a response must
     * fail CLOSED on a broken denylist, never fail open.
     */
    public static function fromPackage(): self
    {
        $file = dirname(__DIR__, 3) . '/resources/fingerprint-denylist.php';
        if (!is_file($file)) {
            throw new RuntimeException('Fingerprint denylist resource missing: ' . $file);
        }

        $denylist = require $file;
        $literals = is_array($denylist) ? (array) ($denylist['literals'] ?? []) : [];
        $patterns = is_array($denylist) ? (array) ($denylist['patterns'] ?? []) : [];
        if ($literals === [] && $patterns === []) {
            throw new RuntimeException(
                'Fingerprint denylist is empty or malformed — refusing to build a no-op guard that '
                . 'would pass every response as clean.'
            );
        }

        return new self($literals, $patterns);
    }

    /**
     * Every denylist signature found in $text.
     *
     * @return string[] the offending signatures (empty ⇒ clean)
     */
    public function scan(string $text): array
    {
        $hits = [];
        foreach ($this->literals as $needle) {
            if (stripos($text, $needle) !== false) {
                $hits[] = $needle;
            }
        }
        foreach ($this->patterns as $pattern) {
            if (@preg_match('~' . $pattern . '~i', $text) === 1) {
                $hits[] = '/' . $pattern . '/';
            }
        }

        return $hits;
    }

    /**
     * Scan a whole response (body + header names/values) and throw on any hit.
     *
     * @param array<string,string> $headers
     */
    public function assertResponseClean(string $body, array $headers, string $context): void
    {
        $texts = [$body];
        foreach ($headers as $name => $value) {
            $texts[] = (string) $name;
            $texts[] = (string) $value;
        }
        foreach ($texts as $text) {
            $hits = $this->scan($text);
            if ($hits !== []) {
                throw new RuntimeException(
                    "Fingerprint leak in {$context}: response text contains " . implode(', ', $hits)
                    . ' — an upstream detector signature must never reach a served response.'
                );
            }
        }
    }
}
