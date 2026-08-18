<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

/**
 * The invertibility verdict for one matcher block, plus the response constraints it
 * contributes when IN. The classifier folds these through `matchers-condition`.
 *
 * A note on regions: body-region and header-region ("all_headers") constraints are
 * kept apart because nuclei matches them against different corpora
 * (body vs the `\n`-joined canonical header block, with no status line).
 */
final class MatcherResult
{
    public bool $ok = true;
    public string $reason = '';

    /** @var string[] substrings required present in the body */
    public array $bodyWords = [];
    /** @var string[] substrings required present in the header block */
    public array $headerWords = [];
    /**
     * Per-typed-header required substrings: canonical header name → substrings that must
     * appear in THAT header's value (nuclei's `part: content_type`/`server`/… regions).
     * Each substring is also mirrored into {@see $headerWords} so the merge, B6 and the
     * runtime validator treat it as header-block-present; this map additionally pins WHICH
     * header the synthesizer must emit it into.
     *
     * @var array<string,string[]>
     */
    public array $typedHeader = [];
    /** @var string[] substrings that must be ABSENT from the body */
    public array $forbidden = [];
    /** @var string[] substrings that must be ABSENT from the header block */
    public array $headerForbidden = [];

    /** @var int[]|null allowed status set (OR-only); null = unconstrained by this matcher */
    public ?array $statusAllowed = null;
    /** @var int[] statuses that must NOT be emitted */
    public array $statusForbidden = [];

    /** @var array{op:string,n:int}|null body-length constraint: op in eq|min|max */
    public ?array $size = null;

    /** @var string[] regex witnesses (validated) to place in the body */
    public array $regexWitness = [];

    /** A1/A4: this matcher constrains the entire body, so its bundle holds nothing else. */
    public bool $wholeBodyExclusive = false;

    public static function in(): self
    {
        return new self();
    }

    public static function out(string $reason): self
    {
        $r = new self();
        $r->ok = false;
        $r->reason = $reason;

        return $r;
    }
}
