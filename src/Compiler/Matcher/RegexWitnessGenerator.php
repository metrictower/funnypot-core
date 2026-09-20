<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler\Matcher;

use Funnypot\Core\Compiler\Crs\FingerprintGuard;
use Funnypot\Core\Compiler\DynamicLiteralScreen;
use Funnypot\Core\Support\SubSeed;

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
    /** @var FingerprintGuard|null the alternate screen; null ⇒ not yet resolved. */
    private $guard;

    /** @var bool whether {@see $guard} has been resolved (may resolve to null on a broken denylist). */
    private $guardResolved;

    /** @var (callable(string,string,string[]):void)|null observer for the RE2 dev/operator audit. */
    private $auditObserver;

    /**
     * @param FingerprintGuard|null $guard   the served-alternate screen; a null default is resolved
     *   lazily from the package denylist and treated as "cannot verify ⇒ drop every alternate" when
     *   the denylist is broken (fail closed — the canonical is screened downstream by Classifier).
     * @param (callable(string,string,string[]):void)|null $auditObserver called with
     *   (originalPattern, canonical, validatedAlternates) after each successful inversion, for the
     *   committed RE2 corpus audit. No-op by default; never touched on the compile/serve path.
     */
    public function __construct(?FingerprintGuard $guard = null, ?callable $auditObserver = null)
    {
        $this->guard = $guard;
        $this->guardResolved = $guard !== null;
        $this->auditObserver = $auditObserver;
    }

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

        $patterns = $m['regex'] ?? [];
        if (!is_array($patterns)) {
            $patterns = [$patterns];
        }
        $patterns = array_values(array_map(static function ($p): string {
            return (string) $p;
        }, $patterns));

        $condition = strtolower((string) ($m['condition'] ?? ''));
        $allRequired = $condition === 'and';

        return $this->invertRegion($region, $patterns, !empty($m['negative']), $allRequired);
    }

    /**
     * Invert one or more regex patterns already resolved to a BODY/HEADER region — the shared core of
     * {@see invert()} (the nuclei @regex matcher) and the DSL `regex(part, …)` function inversion
     * (FP-0261). Patterns combine as AND when $allRequired, else OR (one witness suffices).
     *
     * Each body witness carries an aligned per-deploy MENU of alternates (FP-0280): regexWitness[j] is
     * the canonical and regexWitnessMenu[j] its validated alternates. $lowercaseInput marks a
     * `regex(pattern, tolower(body))` DSL call — the served witness is lowercased and revalidated so the
     * real tolower expression can match it. Header witnesses carry no menu.
     *
     * @param string[] $patterns
     */
    public function invertRegion(string $region, array $patterns, bool $negative, bool $allRequired, bool $lowercaseInput = false): MatcherResult
    {
        if ($region !== PartRouter::BODY && $region !== PartRouter::HEADER) {
            return MatcherResult::out('regex-region-unsupported');
        }
        if ($negative) {
            // Guaranteeing a pattern never matches a synthesized body is not safe offline.
            return MatcherResult::out('regex-negative-unsupported');
        }
        if ($patterns === []) {
            return MatcherResult::out('regex-empty');
        }

        $witnesses = [];
        $menus = [];
        $exclusive = false;
        $lastReason = 'regex-unwitnessable';

        foreach ($patterns as $pattern) {
            $menu = $this->menuForPattern($pattern, $lowercaseInput);
            $w = $menu['canonical'];
            if ($w === null) {
                if ($allRequired) {
                    return MatcherResult::out($menu['reason']);
                }
                $lastReason = $menu['reason'];
                continue;
            }
            if ($region === PartRouter::HEADER) {
                // A header-block witness must be an anchor-free, CRLF/NUL-free substring:
                // it is emitted as a header value and matched anywhere in the block.
                if ($menu['anchoredStart'] || $menu['anchoredEnd'] || !$this->headerSafe($w)) {
                    if ($allRequired) {
                        return MatcherResult::out('regex-header-unsafe');
                    }
                    $lastReason = 'regex-header-unsafe';
                    continue;
                }
            }
            $witnesses[] = $w;
            // Header witnesses carry no menu; body witnesses carry their aligned alternate list.
            $menus[] = $region === PartRouter::HEADER ? [] : $menu['alternates'];
            // Body: only an end-anchor ($) makes the whole body exclusive (A1, unchanged).
            $exclusive = $exclusive || $menu['anchoredEnd'];
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
        $r->regexWitnessMenu = $menus;
        $r->wholeBodyExclusive = $exclusive;

        return $r;
    }

    /**
     * Generate + validate the canonical witness and its alternate menu for one pattern, reporting
     * its start (`^…`) and end (`…$`) anchoring and a typed fold reason. Every candidate is
     * PCRE-revalidated against the ORIGINAL pattern and screened for fingerprint tells / denied
     * digits; a bad canonical folds the pattern (canonical null), a bad alternate is dropped.
     *
     * @return array{canonical: string|null, alternates: string[], anchoredStart: bool, anchoredEnd: bool, reason: string}
     */
    public function menuForPattern(string $pattern, bool $lowercaseInput = false): array
    {
        $fold = static function (string $reason): array {
            return ['canonical' => null, 'alternates' => [], 'anchoredStart' => false, 'anchoredEnd' => false, 'reason' => $reason];
        };

        if (!DynamicLiteralScreen::isResolvable($pattern)) {
            return $fold('regex-dynamic-literal');
        }

        [$core, , $anchoredEnd, $anchoredStart] = $this->strip($pattern);

        $candidates = RegexWitness::generateMenu($core, RegexWitness::MENU_K);
        if ($candidates === []) {
            return $fold('regex-unwitnessable');
        }

        // For a tolower()-wrapped input the served byte is the LOWERCASED witness, matched against the
        // original pattern; re-dedup because lowercasing can collapse two candidates into one.
        if ($lowercaseInput) {
            $candidates = $this->lowercaseCandidates($candidates);
        }

        // Canonical admission is PCRE-only, exactly as the historical single-witness path — so the
        // committed rx set and every fold decision are byte-identical and an operator regen adds only
        // sparse rxm. A denylisted canonical still folds its template downstream via
        // Classifier::hasDenylistedWitness (unchanged). Alternates get the full fingerprint/denied screen
        // here (and again defensively at freeze), since they are NOT covered by that Classifier fold.
        $canonical = $candidates[0];
        if ($canonical === '' || !$this->validate($pattern, $canonical)) {
            return $fold('regex-unwitnessable');
        }

        $alternates = [];
        foreach (array_slice($candidates, 1) as $alt) {
            if ($alt === '' || $alt === $canonical || in_array($alt, $alternates, true)) {
                continue;
            }
            if ($this->admissible($pattern, $alt)) {
                $alternates[] = $alt;
            }
        }

        if ($this->auditObserver !== null) {
            ($this->auditObserver)($pattern, $canonical, $alternates);
        }

        return [
            'canonical' => $canonical,
            'alternates' => $alternates,
            'anchoredStart' => (bool) $anchoredStart,
            'anchoredEnd' => (bool) $anchoredEnd,
            'reason' => '',
        ];
    }

    /**
     * A candidate is admissible when it satisfies the original pattern under PCRE, carries no
     * fingerprint-denylist tell, and holds no denied bare-digit token.
     */
    private function admissible(string $pattern, string $witness): bool
    {
        if (!$this->validate($pattern, $witness)) {
            return false;
        }
        if (SubSeed::hitsDeniedDigits($witness)) {
            return false;
        }
        $guard = $this->guard();
        if ($guard === null) {
            // Broken denylist: fail closed — an alternate we cannot verify is dropped, and the
            // canonical is screened downstream by Classifier's witness fold.
            return false;
        }

        return $guard->scan($witness) === [];
    }

    /**
     * Lowercase each candidate (the tolower(body) served byte) and re-dedup while preserving order.
     *
     * @param list<string> $candidates
     * @return list<string>
     */
    private function lowercaseCandidates(array $candidates): array
    {
        $seen = [];
        $out = [];
        foreach ($candidates as $c) {
            $lc = strtolower($c);
            if (!isset($seen[$lc])) {
                $seen[$lc] = true;
                $out[] = $lc;
            }
        }

        return $out;
    }

    /** Lazily resolve the alternate screen from the package denylist (null on a broken denylist). */
    private function guard(): ?FingerprintGuard
    {
        if (!$this->guardResolved) {
            $this->guard = FingerprintGuard::tryFromPackage();
            $this->guardResolved = true;
        }

        return $this->guard;
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
}
