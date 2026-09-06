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
 * This backs the compile-time lint (CrsCompiler::assertResponseClean, mirroring EmulatorCompiler's
 * own "compiles but silently wrong = build failure" screens), the Gate-B witness fold
 * (Classifier::finalize), the CI script scripts/ci/check-fingerprint-safety.php, and the runtime
 * egress guard (Honeypot::buildFake) — so one denylist governs every path.
 *
 * Host-injected synthesizers (the app LLM tier can fabricate "blocked by ModSecurity/CRS") MUST
 * route their output through scanResponse() before serving and fail CLOSED on any hit AND on a
 * load failure: a fabricated body carrying a detector signature must never reach the wire.
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
     * Load the package denylist for a HOT-PATH caller, returning null instead of throwing on a
     * missing/broken denylist. A runtime guard (egress scan, decoy-body verify) must not turn a
     * would-be 404 into a 500 — a 500 is itself a tell — so it treats null as "cannot verify" and
     * fails closed to the plain 404. The load-once/try-catch caching is the caller's (Honeypot,
     * TemplateAttackEmulator), so a broken denylist is not re-required on every request.
     */
    public static function tryFromPackage(): ?self
    {
        try {
            return self::fromPackage();
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Scan a whole response (body + header names/values) WITHOUT throwing — the non-fatal twin of
     * assertResponseClean, for the runtime egress guard where a throw would surface as a 500. A
     * header value may be a single line or a list of lines (SynthesizedResponse allows both).
     *
     * @param array<string,string|string[]> $headers
     * @return string[] the offending signatures across the whole response (empty ⇒ clean)
     */
    public function scanResponse(string $body, array $headers): array
    {
        $hits = $this->scan($body);
        foreach ($headers as $name => $value) {
            $hits = array_merge($hits, $this->scan((string) $name));
            foreach (is_array($value) ? $value : [$value] as $line) {
                $hits = array_merge($hits, $this->scan((string) $line));
            }
        }

        return $hits;
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
