<?php

declare(strict_types=1);

namespace Funnypot\Synthesis;

use Funnypot\Detection;
use Funnypot\Response\BundleValidator;
use Funnypot\Response\EmulatorRegistry;
use Funnypot\Response\Style;
use Funnypot\SynthesizedResponse;

/**
 * Turns one compiled bundle into a fake response that satisfies its matchers.
 *
 * Two layers:
 *   1. When a response style beyond MINIMAL is set and an endpoint emulator recognises
 *      the bundle, render rich believable content (a real-looking .env / .git/config /
 *      xmlrpc). The rich output is VALIDATED against the bundle before use; if it does
 *      not fit, we fall through to (2) — richness can never break the matcher guarantee.
 *   2. Minimal synthesis: status + word(part:body) + forbidden substrings (+ header
 *      words, typed headers, regex witnesses, and a body-size constraint). The assembled
 *      response is re-validated against the bundle before serving; a bundle that still
 *      cannot be satisfied is SKIPPED with a recorded reason rather than emitted wrong.
 *
 * Matcher semantics honoured (validated against real nuclei):
 *   - word(part:body)  -> substring must appear in the body, verbatim casing.
 *   - status           -> exactly one status line ('s', default 200).
 *   - forbidden ('nf') -> substring (case-insensitive, matching dsl tolower and
 *                         case-insensitive negative words) must be ABSENT from body.
 *   - word(part:header)/'hw' -> substring must appear in the header block, which
 *                         nuclei builds as HeadersToString: "Key: value" lines,
 *                         \n-joined, Go-canonical keys, NO status line.
 *   - 'hf'             -> forbidden header-block substring, must be ABSENT.
 *   - typed header ('th') -> canonical-name → substrings the matched response header's
 *                         VALUE must contain (nuclei `part: content_type`/`server`/…);
 *                         emitted into that exact header.
 *   - regex witness ('rx') -> a validated literal witness placed in the body; an
 *                         unanchored regex finds it as a substring.
 *   - size ('sz')      -> body length constraint: pad up to min/eq, bound by max.
 * Every synthesized header name+value is asserted CR/LF/NUL-free (C8).
 */
final class ResponseSynthesizer
{
    private string $lastSkipReason = '';
    private ?EmulatorRegistry $emulators;
    private string $style;
    private ?string $serverHeader;
    private ?string $poweredBy;

    public function __construct(
        ?EmulatorRegistry $emulators = null,
        string $style = Style::MINIMAL,
        ?string $serverHeader = null,
        ?string $poweredBy = null
    ) {
        $this->emulators = $emulators;
        $this->style = Style::isValid($style) ? $style : Style::MINIMAL;
        $this->serverHeader = $serverHeader;
        $this->poweredBy = $poweredBy;
    }

    /**
     * @param array<string,mixed> $bundle a single compiled bundle (entry['b'][i])
     * @param string              $seed   persona seed for deterministic fake values
     * @return SynthesizedResponse|null null => this bundle is out of minimal-synth scope
     */
    public function synthesize(array $bundle, Detection $satisfies, string $seed = ''): ?SynthesizedResponse
    {
        $this->lastSkipReason = '';

        // Rich emulator layer (validated; falls through to minimal on any mismatch).
        if ($this->style !== Style::MINIMAL && $this->emulators !== null) {
            $rich = $this->tryEmulator($bundle, $satisfies, $seed);
            if ($rich !== null) {
                return $rich;
            }
        }

        $bodyWords = array_values(array_map('strval', (array) ($bundle['bw'] ?? [])));
        $forbidden = array_values(array_map('strval', (array) ($bundle['nf'] ?? [])));
        $witnesses = array_values(array_map('strval', (array) ($bundle['rx'] ?? [])));
        $size = $this->normalizeSize($bundle['sz'] ?? null);
        $exclusive = !empty($bundle['x']);

        // rx witnesses are plain body strings, satisfied by their literal presence. The
        // required body content is the words plus the witnesses.
        $required = array_merge($bodyWords, $witnesses);

        // Intra-bundle satisfiability (B6): a required substring cannot also be forbidden.
        foreach ($required as $word) {
            foreach ($forbidden as $bad) {
                if ($bad !== '' && stripos($word, $bad) !== false) {
                    return $this->skip("required body content '{$word}' contains forbidden '{$bad}'");
                }
            }
        }

        $body = $this->assembleBody($bodyWords, $witnesses, $exclusive, $size);
        if ($body === null) {
            return null; // reason already set
        }

        if ($size !== null) {
            $body = $this->applySize($body, $size, $forbidden);
            if ($body === null) {
                return null; // reason already set
            }
        }

        // Assert the assembled body carries none of the forbidden substrings.
        // nuclei checks these case-insensitively (dsl tolower / case-insensitive negative).
        foreach ($forbidden as $bad) {
            if ($bad !== '' && stripos($body, $bad) !== false) {
                return $this->skip("body contains forbidden substring '{$bad}'");
            }
        }

        $status = (int) ($bundle['s'] ?? 200);

        $headers = $this->buildHeaders($bundle);
        if ($headers === null) {
            return null; // reason already set
        }

        // Final gate: the whole (body, headers) must satisfy the bundle's block-level
        // constraints, and every typed header must carry its required value.
        if (!BundleValidator::satisfies($body, $headers, $bundle)) {
            return $this->skip('assembled response failed bundle validation');
        }
        if (!$this->typedHeadersSatisfied($headers, $bundle)) {
            return null; // reason already set
        }

        return new SynthesizedResponse($status, $headers, $body, $satisfies);
    }

    /**
     * Build the response body from required words and regex witnesses.
     *
     * A whole-body-exclusive bundle (`x`) whose exclusivity comes from an anchored regex
     * (rx present, no size) must be served as exactly its single witness — appending any
     * other content would break a `^…`/`…$` anchor, and we cannot re-run the regex offline.
     * When that is not possible, skip. Everything else joins words and unanchored witnesses.
     *
     * @param string[] $bodyWords
     * @param string[] $witnesses
     * @param array{op:string,n:int}|null $size
     */
    private function assembleBody(array $bodyWords, array $witnesses, bool $exclusive, ?array $size): ?string
    {
        if ($witnesses !== [] && $exclusive && $size === null) {
            if (count($witnesses) !== 1 || $bodyWords !== []) {
                return $this->skip('anchored regex witness cannot be offline-satisfied with extra body content');
            }

            return $witnesses[0];
        }

        return $this->buildBody(array_merge($bodyWords, $witnesses));
    }

    /**
     * Normalize a frozen size constraint (`['eq'|'min'|'max' => N]`) to `['op'=>…,'n'=>…]`.
     *
     * @param mixed $sz
     * @return array{op:string,n:int}|null
     */
    private function normalizeSize($sz): ?array
    {
        if (!is_array($sz) || $sz === []) {
            return null;
        }
        $op = (string) array_key_first($sz);
        if (!in_array($op, ['eq', 'min', 'max'], true)) {
            return null;
        }

        return ['op' => $op, 'n' => (int) $sz[$op]];
    }

    /**
     * Enforce a body-length constraint after the required content is placed: pad up to a
     * min/eq target with filler that introduces no forbidden substring; reject when the
     * required content already exceeds an exact/max bound.
     *
     * @param array{op:string,n:int} $size
     * @param string[] $forbidden
     */
    private function applySize(string $body, array $size, array $forbidden): ?string
    {
        $len = strlen($body);
        $n = $size['n'];

        if ($size['op'] === 'max') {
            return $len > $n ? $this->skip("body length {$len} exceeds max size {$n}") : $body;
        }
        if ($size['op'] === 'eq' && $len > $n) {
            return $this->skip("required body length {$len} exceeds exact size {$n}");
        }
        if ($len >= $n) {
            return $body; // min already met (eq over-length handled above)
        }

        $filler = $this->fillerChar($forbidden);
        if ($filler === null) {
            return $this->skip('no forbidden-safe padding filler available');
        }

        return $body . str_repeat($filler, $n - $len);
    }

    /**
     * A single-byte filler that cannot appear inside any forbidden substring — so a run of
     * it never forms one, even across the body/padding boundary. Null if all candidates
     * occur in a forbidden string.
     *
     * @param string[] $forbidden
     */
    private function fillerChar(array $forbidden): ?string
    {
        foreach ([' ', '.', '-', '#', '/', '=', ';', '0', 'x', 'z'] as $c) {
            $safe = true;
            foreach ($forbidden as $bad) {
                if ($bad !== '' && stripos($bad, $c) !== false) {
                    $safe = false;
                    break;
                }
            }
            if ($safe) {
                return $c;
            }
        }

        return null;
    }

    public function lastSkipReason(): string
    {
        return $this->lastSkipReason;
    }

    /**
     * Render rich content from a matching emulator, validated against the bundle. Any
     * mismatch returns null so the caller falls back to guaranteed-correct minimal synth.
     *
     * @param array<string,mixed> $bundle
     */
    private function tryEmulator(array $bundle, Detection $satisfies, string $seed): ?SynthesizedResponse
    {
        $emulator = $this->emulators->find($bundle);
        if ($emulator === null) {
            return null;
        }

        $content = $emulator->render($bundle, $this->style, crc32($seed));
        if ($content === null) {
            return null;
        }

        // Base headers (satisfy hw / default content-type), then overlay the emulator's.
        $base = $this->buildHeaders($bundle);
        if ($base === null) {
            return null;
        }
        $headers = $base;
        foreach ($content->headers as $name => $value) {
            $headers[$this->canonicalKey((string) $name)] = (string) $value;
        }

        // Rich content must satisfy every constraint the validator knows (bw/nf/hw/hf), the
        // typed-header values, and the regex-witness / size shapes it does not — otherwise
        // fall back to guaranteed-correct minimal synthesis.
        if (!BundleValidator::satisfies($content->body, $headers, $bundle)) {
            return null;
        }
        if (!$this->typedHeadersSatisfied($headers, $bundle)) {
            return null;
        }
        if (!$this->richBodyFitsExtras($content->body, $bundle)) {
            return null;
        }

        return new SynthesizedResponse((int) ($bundle['s'] ?? 200), $headers, $content->body, $satisfies);
    }

    /**
     * True when a rich emulator body already carries every regex witness and respects the
     * size constraint; a miss sends the caller back to minimal synthesis (which pads /
     * places witnesses deterministically).
     *
     * @param array<string,mixed> $bundle
     */
    private function richBodyFitsExtras(string $body, array $bundle): bool
    {
        foreach (array_map('strval', (array) ($bundle['rx'] ?? [])) as $witness) {
            if ($witness !== '' && strpos($body, $witness) === false) {
                return false;
            }
        }
        $size = $this->normalizeSize($bundle['sz'] ?? null);
        if ($size !== null) {
            $len = strlen($body);
            if ($size['op'] === 'eq' && $len !== $size['n']) {
                return false;
            }
            if ($size['op'] === 'min' && $len < $size['n']) {
                return false;
            }
            if ($size['op'] === 'max' && $len > $size['n']) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param string[] $bodyWords
     */
    private function buildBody(array $bodyWords): string
    {
        // Order is irrelevant to `contains` matching; a newline join reads like a
        // real config/text file and keeps distinct words from fusing into one token.
        return implode("\n", $bodyWords);
    }

    /**
     * @param array<string,mixed> $bundle
     * @return array<string,string>|null null on an unsatisfiable/unsafe header set
     */
    private function buildHeaders(array $bundle): ?array
    {
        /** @var array<string,string> $headers canonical-key => value */
        $headers = [];

        // Base: invented headers carried by the bundle.
        foreach ((array) ($bundle['h'] ?? []) as $name => $value) {
            $headers[$this->canonicalKey((string) $name)] = (string) $value;
        }

        // Typed headers: emit each required substring into the value of its own header, so
        // nuclei's per-header value match (`part: content_type`/`server`/…) is satisfied.
        foreach ((array) ($bundle['th'] ?? []) as $name => $subs) {
            $canonical = $this->canonicalKey((string) $name);
            $headers[$canonical] = $this->composeTypedValue(
                $headers[$canonical] ?? null,
                array_map('strval', (array) $subs)
            );
        }

        $headerWords = array_values(array_map('strval', (array) ($bundle['hw'] ?? [])));
        $headerForbidden = array_values(array_map('strval', (array) ($bundle['hf'] ?? [])));

        // A header word that looks like a MIME type is most plausibly the Content-Type.
        foreach ($headerWords as $word) {
            if (!isset($headers['Content-Type']) && $this->looksLikeMime($word)) {
                $headers['Content-Type'] = $word;
                break;
            }
        }

        // Plausible default for an exposed-file response.
        if (!isset($headers['Content-Type'])) {
            $headers['Content-Type'] = 'text/plain';
        }

        // Guarantee every header word appears somewhere in the header block. Any
        // still-missing one is injected as its own header value (substring match
        // is all nuclei needs on the all_headers region).
        $synthetic = 0;
        foreach ($headerWords as $word) {
            if ($word === '') {
                continue;
            }
            if (strpos($this->headerBlock($headers), $word) === false) {
                $headers[$this->canonicalKey('X-Detected-' . (++$synthetic))] = $word;
            }
        }

        // hf: a forbidden header-block substring must not be present.
        foreach ($headerForbidden as $bad) {
            if ($bad !== '' && stripos($this->headerBlock($headers), $bad) !== false) {
                return $this->skip("header block contains forbidden '{$bad}'");
            }
        }

        // Per-response cosmetic salt: a realistic, always-safe varying header so the full
        // response is never byte-identical across requests. Once funnypot is public its
        // deterministic bodies would otherwise be catalogued by content hash; a varying
        // request id (like real servers send) breaks that. Pure hex — cannot contain a
        // forbidden/hf substring or a CRLF, and never a matcher target.
        // Coherent server identity: one host presents one Server banner (+ optional
        // X-Powered-By) on every response, so header recon can't catch a bare PHP server
        // sitting behind a product fake. A bundle/emulator header still wins if it set one.
        if ($this->serverHeader !== null && !isset($headers['Server'])) {
            $headers['Server'] = $this->serverHeader;
        }
        if ($this->poweredBy !== null && !isset($headers['X-Powered-By'])) {
            $headers['X-Powered-By'] = $this->poweredBy;
        }

        if (!isset($headers['X-Request-Id'])) {
            $headers['X-Request-Id'] = bin2hex(random_bytes(8));
        }

        // C8: no synthesized header name/value may carry CR, LF, or NUL.
        foreach ($headers as $name => $value) {
            if (preg_match('/[\r\n\x00]/', $name) === 1 || preg_match('/[\r\n\x00]/', $value) === 1) {
                return $this->skip('header name/value violates CR/LF/NUL safety (C8)');
            }
        }

        return $headers;
    }

    /**
     * Compose one typed-header value that contains every required substring, keeping any
     * value already carried by the bundle's invented headers. Substrings already covered by
     * the running value are not re-appended.
     *
     * @param string[] $subs
     */
    private function composeTypedValue(?string $existing, array $subs): string
    {
        $value = $existing ?? '';
        foreach ($subs as $s) {
            if ($s === '' || ($value !== '' && strpos($value, $s) !== false)) {
                continue;
            }
            $value = $value === '' ? $s : $value . '; ' . $s;
        }

        return $value;
    }

    /**
     * Verify each typed header's value literally contains its required substrings — the
     * sufficient condition nuclei's per-header value match checks (the block-level validator
     * only proves the substring is present SOMEWHERE in the header block).
     *
     * @param array<string,string> $headers
     * @param array<string,mixed>  $bundle
     */
    private function typedHeadersSatisfied(array $headers, array $bundle): bool
    {
        foreach ((array) ($bundle['th'] ?? []) as $name => $subs) {
            $canonical = $this->canonicalKey((string) $name);
            $value = $headers[$canonical] ?? null;
            if ($value === null) {
                $this->skip("typed header '{$canonical}' was not emitted");

                return false;
            }
            foreach (array_map('strval', (array) $subs) as $s) {
                if ($s !== '' && strpos($value, $s) === false) {
                    $this->skip("typed header '{$canonical}' missing required '{$s}'");

                    return false;
                }
            }
        }

        return true;
    }

    /**
     * nuclei's all_headers region: canonical "Key: value" lines, \n-joined,
     * no status line. Used only to test substring presence during synthesis.
     *
     * @param array<string,string> $headers
     */
    private function headerBlock(array $headers): string
    {
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name . ': ' . $value;
        }

        return implode("\n", $lines);
    }

    /**
     * Go textproto.CanonicalMIMEHeaderKey: upper-case the first letter and each
     * letter after a hyphen, lower-case the rest. nuclei matches against keys in
     * this exact form.
     */
    private function canonicalKey(string $name): string
    {
        $out = '';
        $upperNext = true;
        $len = strlen($name);
        for ($i = 0; $i < $len; $i++) {
            $ch = $name[$i];
            if ($ch === '-') {
                $out .= $ch;
                $upperNext = true;
                continue;
            }
            $out .= $upperNext ? strtoupper($ch) : strtolower($ch);
            $upperNext = false;
        }

        return $out;
    }

    private function looksLikeMime(string $value): bool
    {
        return preg_match('#^[a-z0-9.+-]+/[a-z0-9.+-]+$#i', $value) === 1;
    }

    private function skip(string $reason): ?SynthesizedResponse
    {
        $this->lastSkipReason = $reason;

        return null;
    }
}
