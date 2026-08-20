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
    /** @var bool */
    public $ok = true;
    /** @var string */
    public $reason = '';

    /** @var string[] substrings required present in the body */
    public $bodyWords = [];
    /** @var string[] substrings required present in the header block */
    public $headerWords = [];
    /**
     * Per-typed-header required substrings: canonical header name → substrings that must
     * appear in THAT header's value (nuclei's `part: content_type`/`server`/… regions).
     * Each substring is also mirrored into {@see $headerWords} so the merge, B6 and the
     * runtime validator treat it as header-block-present; this map additionally pins WHICH
     * header the synthesizer must emit it into.
     *
     * @var array<string,string[]>
     */
    public $typedHeader = [];
    /** @var string[] substrings that must be ABSENT from the body */
    public $forbidden = [];
    /** @var string[] substrings that must be ABSENT from the header block */
    public $headerForbidden = [];

    /** @var int[]|null allowed status set (OR-only); null = unconstrained by this matcher */
    public $statusAllowed = null;
    /** @var int[] statuses that must NOT be emitted */
    public $statusForbidden = [];

    /** @var array{op:string,n:int}|null body-length constraint: op in eq|min|max */
    public $size = null;

    /** @var string[] regex witnesses (validated) to place in the body */
    public $regexWitness = [];

    /** @var bool A1/A4: this matcher constrains the entire body, so its bundle holds nothing else. */
    public $wholeBodyExclusive = false;

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
