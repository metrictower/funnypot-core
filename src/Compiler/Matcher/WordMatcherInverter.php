<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

use Funnypot\Compiler\DynamicLiteralScreen;

/**
 * Inverts a `word` matcher block (match.go `MatchWords`).
 *
 * Semantics honored:
 *   - part routing (body|header|all) via {@see PartRouter}
 *   - typed-header parts (content_type|server|location|set_cookie|…): the word must appear
 *     in that one header's VALUE. Positive words are pinned to the header via the result's
 *     typedHeader map (and mirrored into the header block); negatives fold — we cannot
 *     guarantee a specific header's absence offline without over-constraining the block.
 *   - part: response — the raw response dump (status line + headers + body). A positive
 *     word placed in the body is also a substring of that dump, so it routes to the body;
 *     a negative would have to hold over the whole dump, so it folds.
 *   - condition and / match-all ⇒ every word required; or (default) ⇒ one word suffices
 *   - case-insensitive ⇒ words are compared lowercased, so emit the lowercase form
 *   - encoding: hex ⇒ words are hex-decoded to raw bytes at compile time
 *   - negative ⇒ the words must be ABSENT (a response emitting none of them satisfies
 *     both the OR and AND readings of the reversed matcher)
 *
 * Screen A2: a required word carrying an unresolvable `{{…}}` folds the matcher OUT
 * (AND) or is dropped (OR). Under negative, an unresolvable word is simply dropped —
 * a value we never emit is guaranteed absent.
 */
final class WordMatcherInverter
{
    private const MAX_AND_WORDS = 256;

    /**
     * @param array<string,mixed> $m
     */
    public function invert(array $m): MatcherResult
    {
        $partRaw = strtolower(trim((string) ($m['part'] ?? '')));
        $typed = PartRouter::typedHeader($partRaw);
        $isResponse = $partRaw === 'response';
        $region = ($typed !== null || $isResponse) ? PartRouter::BODY : PartRouter::region($partRaw);

        if ($typed === null && !$isResponse && $region === PartRouter::UNSUPPORTED) {
            return MatcherResult::out('word-part-unsupported:' . $partRaw);
        }

        $words = $m['words'] ?? [];
        if (!is_array($words)) {
            $words = [$words];
        }
        $words = array_values(array_map(static fn ($w): string => (string) $w, $words));
        if ($words === []) {
            return MatcherResult::out('word-empty');
        }

        $hex = strtolower((string) ($m['encoding'] ?? '')) === 'hex';
        $ci = !empty($m['case-insensitive']);
        $negative = !empty($m['negative']);
        $condition = strtolower((string) ($m['condition'] ?? ''));
        $allRequired = ($condition === 'and') || !empty($m['match-all']);

        // Decode / normalize each word to the literal that must appear in the response.
        $decoded = [];
        foreach ($words as $w) {
            if ($hex) {
                $bytes = @hex2bin(preg_replace('/\s+/', '', $w) ?? '');
                if ($bytes === false || $bytes === '') {
                    // A word we cannot decode cannot be emitted.
                    if ($allRequired && !$negative) {
                        return MatcherResult::out('word-hex-undecodable');
                    }
                    continue;
                }
                $w = $bytes;
            }
            if ($ci) {
                $w = strtolower($w);
            }
            $decoded[] = $w;
        }
        if ($decoded === []) {
            return MatcherResult::out('word-empty');
        }

        $r = MatcherResult::in();

        if ($negative) {
            // Typed-header / raw-response negatives cannot be honoured without emitting the
            // exact header (or controlling the whole dump); fold rather than under-constrain.
            if ($typed !== null) {
                return MatcherResult::out('word-typed-negative:' . $partRaw);
            }
            if ($isResponse) {
                return MatcherResult::out('word-response-negative');
            }
            foreach ($decoded as $w) {
                if (!DynamicLiteralScreen::isResolvable($w)) {
                    continue; // unpredictable value we never emit ⇒ already absent
                }
                $this->addForbidden($r, $region, $w);
            }
            // If every forbidden word was unresolvable there is nothing to enforce,
            // which is fine: the reversed matcher is already satisfied.
            return $r;
        }

        // Positive words.
        $resolvable = array_values(array_filter(
            $decoded,
            static fn (string $w): bool => DynamicLiteralScreen::isResolvable($w)
        ));

        // A3: the header/all corpus (all_headers) is `Key: value\n` with NO status line,
        // so a word that is the status-line token can never match there — fold it. Typed
        // headers hold only a value (never the status line), so the same guard applies.
        if ($region === PartRouter::HEADER || $typed !== null) {
            foreach ($resolvable as $w) {
                if ($this->isStatusLineToken($w)) {
                    return MatcherResult::out('word-header-status-line');
                }
            }
        }

        if ($allRequired) {
            if (count($resolvable) !== count($decoded)) {
                return MatcherResult::out('word-dynamic-literal');
            }
            if (count($resolvable) > self::MAX_AND_WORDS) {
                return MatcherResult::out('word-and-too-many');
            }
            foreach ($resolvable as $w) {
                $this->place($r, $typed, $region, $w);
            }

            return $r;
        }

        // OR: one word is enough — take the first resolvable one.
        if ($resolvable === []) {
            return MatcherResult::out('word-dynamic-literal');
        }
        $this->place($r, $typed, $region, $resolvable[0]);

        return $r;
    }

    /**
     * A status line begins with the HTTP-version token (`HTTP/1.1 200 OK`). Match only a
     * leading `HTTP/<digit>` so real header values like `Server: ... aiohttp/3.8` — which
     * merely contain `HTTP/` mid-string — are left alone.
     */
    private function isStatusLineToken(string $w): bool
    {
        return (bool) preg_match('~^HTTP/[0-9]~', $w);
    }

    /**
     * Route a required word to its destination: a typed header pins the word to that
     * header's value (and mirrors it into the block so the block-level machinery sees it);
     * otherwise it is a plain body or header-block substring.
     */
    private function place(MatcherResult $r, ?string $typed, string $region, string $w): void
    {
        if ($typed !== null) {
            $r->typedHeader[$typed][] = $w;
            $r->headerWords[] = $w;

            return;
        }
        $this->addRequired($r, $region, $w);
    }

    private function addRequired(MatcherResult $r, string $region, string $w): void
    {
        if ($region === PartRouter::HEADER) {
            $r->headerWords[] = $w;
        } else {
            $r->bodyWords[] = $w;
        }
    }

    private function addForbidden(MatcherResult $r, string $region, string $w): void
    {
        if ($region === PartRouter::HEADER) {
            $r->headerForbidden[] = $w;
        } else {
            $r->forbidden[] = $w;
        }
    }
}
