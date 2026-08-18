<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

use Funnypot\Compiler\DynamicLiteralScreen;

/**
 * Inverts a `regex` matcher block (match.go `MatchRegex`, which fires on
 * `FindAllString != ∅` — an UNANCHORED search anywhere in the part).
 *
 * For each pattern we generate one witness with {@see RegexWitness} and re-validate it
 * with PHP `preg_match` as an interim oracle. Go compiles regex with RE2; PHP uses
 * PCRE. They agree on the simple subset we accept but can diverge on edge cases, so a
 * witness that fails PCRE validation folds the matcher OUT, and the real gate remains
 * the Phase 6 nuclei golden test.
 *
 * Anchoring (A1): a pattern anchored with `$` (or `^…$`) constrains the whole body, so
 * the result is marked whole-body-exclusive and its bundle holds nothing else.
 *
 * `part: header` (the `all_headers` block) is also supported for UNANCHORED patterns whose
 * witness is CRLF/NUL-free: nuclei searches the block with `FindAllString`, so a witness
 * emitted as a header value (a block substring) satisfies it. The witness is carried as a
 * plain header-block word (`hw`), reusing the header-word machinery. Anchored header
 * regex (`^…`/`…$`) folds — a block-position guarantee is not safe offline. A typed-header
 * regex (`content_type`/`server`/…) also folds (per spec, unless trivially literal).
 */
final class RegexWitnessGenerator
{
    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        $partRaw = strtolower(trim((string) ($m['part'] ?? '')));

        // Typed-header regex is out of scope: fold it.
        if (PartRouter::typedHeader($partRaw) !== null) {
            return MatcherResult::out('regex-part-unsupported:' . $partRaw);
        }

        $region = PartRouter::region($partRaw);
        if ($region !== PartRouter::BODY && $region !== PartRouter::HEADER) {
            return MatcherResult::out('regex-part-unsupported:' . $partRaw);
        }

        if (!empty($m['negative'])) {
            // Guaranteeing a pattern never matches a synthesized body is not safe offline.
            return MatcherResult::out('regex-negative-unsupported');
        }

        $patterns = $m['regex'] ?? [];
        if (!is_array($patterns)) {
            $patterns = [$patterns];
        }
        $patterns = array_values(array_map(static fn ($p): string => (string) $p, $patterns));
        if ($patterns === []) {
            return MatcherResult::out('regex-empty');
        }

        $condition = strtolower((string) ($m['condition'] ?? ''));
        $allRequired = $condition === 'and';

        $witnesses = [];
        $exclusive = false;
        $lastReason = 'regex-unwitnessable';

        foreach ($patterns as $pattern) {
            $w = $this->witnessFor($pattern, $anchoredEnd, $anchoredStart);
            if ($w === null) {
                if ($allRequired) {
                    return MatcherResult::out($this->reasonFor($pattern));
                }
                $lastReason = $this->reasonFor($pattern);
                continue;
            }
            if ($region === PartRouter::HEADER) {
                // A header-block witness must be an anchor-free, CRLF/NUL-free substring:
                // it is emitted as a header value and matched anywhere in the block.
                if ($anchoredStart || $anchoredEnd || !$this->headerSafe($w)) {
                    if ($allRequired) {
                        return MatcherResult::out('regex-header-unsafe');
                    }
                    $lastReason = 'regex-header-unsafe';
                    continue;
                }
            }
            $witnesses[] = $w;
            // Body: only an end-anchor ($) makes the whole body exclusive (A1, unchanged).
            $exclusive = $exclusive || $anchoredEnd;
            if (!$allRequired) {
                break; // OR: one witness is enough
            }
        }

        if ($witnesses === []) {
            return MatcherResult::out($lastReason);
        }

        $r = MatcherResult::in();
        if ($region === PartRouter::HEADER) {
            // Header-block witnesses are plain block substrings; never whole-body-exclusive.
            $r->headerWords = $witnesses;

            return $r;
        }
        $r->regexWitness = $witnesses;
        $r->wholeBodyExclusive = $exclusive;

        return $r;
    }

    /**
     * Generate + validate a witness for one pattern, reporting its start (`^…`) and end
     * (`…$`) anchoring separately.
     */
    private function witnessFor(string $pattern, ?bool &$anchoredEnd, ?bool &$anchoredStart): ?string
    {
        $anchoredEnd = false;
        $anchoredStart = false;

        if (!DynamicLiteralScreen::isResolvable($pattern)) {
            return null;
        }

        [$core, $flags, $anchoredEnd, $anchoredStart] = $this->strip($pattern);

        $witness = RegexWitness::generate($core);
        if ($witness === null || $witness === '') {
            return null;
        }

        return $this->validate($pattern, $witness) ? $witness : null;
    }

    /** A header value may hold no CR, LF, or NUL (C8). */
    private function headerSafe(string $witness): bool
    {
        return preg_match('/[\r\n\x00]/', $witness) !== 1;
    }

    /**
     * Split a pattern into [core, inline-flags, anchoredAtEnd, anchoredAtStart]. Leading
     * `(?i)`-style flag groups and `^`/`$` anchors are lifted off so the generator sees
     * plain body.
     */
    private function strip(string $pattern): array
    {
        $flags = '';
        // Leading inline flag group: (?i) (?im) (?s) …
        if (preg_match('/^\(\?([imsxU]+)\)/', $pattern, $mm)) {
            $flags = $mm[1];
            $pattern = substr($pattern, strlen($mm[0]));
        }

        $anchoredStart = false;
        if ($pattern !== '' && $pattern[0] === '^') {
            $anchoredStart = true;
            $pattern = substr($pattern, 1);
        }
        $anchoredEnd = false;
        if ($pattern !== '' && substr($pattern, -1) === '$' && substr($pattern, -2) !== '\\$') {
            $anchoredEnd = true;
            $pattern = substr($pattern, 0, -1);
        }

        return [$pattern, $flags, $anchoredEnd, $anchoredStart];
    }

    /**
     * Validate the witness against the ORIGINAL pattern with PCRE. Returns false when
     * the pattern is not PCRE-compilable or the witness does not match.
     */
    private function validate(string $pattern, string $witness): bool
    {
        $delim = $this->pickDelimiter($pattern);
        if ($delim === null) {
            return false;
        }

        // `u` is intentionally omitted: nuclei corpora are byte strings, and our
        // witnesses may contain raw bytes from \xHH.
        $result = @preg_match($delim . $pattern . $delim, $witness);
        if ($result === false) {
            return false; // pattern not valid PCRE
        }

        return $result === 1;
    }

    private function pickDelimiter(string $pattern): ?string
    {
        foreach (['~', '#', '%', '`', '!', '@'] as $d) {
            if (strpos($pattern, $d) === false) {
                return $d;
            }
        }

        return null;
    }

    private function reasonFor(string $pattern): string
    {
        if (!DynamicLiteralScreen::isResolvable($pattern)) {
            return 'regex-dynamic-literal';
        }

        return 'regex-unwitnessable';
    }
}
