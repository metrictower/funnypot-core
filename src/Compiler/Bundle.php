<?php

declare(strict_types=1);

namespace Funnypot\Core\Compiler;

use Funnypot\Core\Detection;

/**
 * One conflict-free persona: a set of template plans that can be satisfied by a SINGLE
 * coherent response. The merge fills these; the compiler freezes each to a schema-1
 * bundle array.
 */
final class Bundle
{
    /** Emitted-body word cap (§2). `t` still records every routed template. */
    private const BODY_WORD_CAP = 64;

    /** @var int|null */
    public $status = null;
    /** @var string[] */
    public $bodyWords = [];
    /** @var string[] */
    public $headerWords = [];
    /** @var string[] */
    public $forbidden = [];
    /** @var string[] */
    public $headerForbidden = [];
    /** @var string[] */
    public $regexWitness = [];
    /** @var array<string,string[]> canonical header name → required substrings in that header */
    public $typedHeader = [];
    /** @var array{op:string,n:int}|null */
    public $size = null;
    /** @var bool */
    public $wholeBodyExclusive = false;
    /** @var string */
    public $product = '';
    /** @var string */
    public $severity = '';
    /** @var string[] provenance: routed template ids */
    public $templateIds = [];

    public function isEmpty(): bool
    {
        return $this->templateIds === [];
    }

    /**
     * Fold a plan's constraints into this bundle. Callers must have checked
     * {@see BundlePartitioner::compatible()} first.
     */
    public function add(SatisfyPlan $plan): void
    {
        if ($this->status === null && $plan->status !== null) {
            $this->status = $plan->status;
        }

        $this->bodyWords = $this->capMerge($this->bodyWords, $plan->bodyWords);
        $this->regexWitness = $this->capMerge($this->regexWitness, $plan->regexWitness);
        $this->headerWords = $this->capMerge($this->headerWords, $plan->headerWords);
        $this->forbidden = $this->union($this->forbidden, $plan->forbidden);
        $this->headerForbidden = $this->union($this->headerForbidden, $plan->headerForbidden);
        $this->typedHeader = $this->mergeTyped($this->typedHeader, $plan->typedHeader);

        if ($plan->size !== null) {
            $combined = ConstraintMerge::combineSize($this->size, $plan->size);
            // Compatibility was pre-checked, so combined is never false here.
            $this->size = $combined === false ? $this->size : $combined;
        }

        $this->wholeBodyExclusive = $this->wholeBodyExclusive || $plan->wholeBodyExclusive;

        if ($this->product === '' && $plan->product !== '') {
            $this->product = $plan->product;
        }

        $this->severity = $this->severity === ''
            ? $plan->severity
            : Detection::ceilingSeverity($this->severity, $plan->severity);

        if (!in_array($plan->id, $this->templateIds, true)) {
            $this->templateIds[] = $plan->id;
        }
    }

    /**
     * @param string[] $into
     * @param string[] $add
     * @return string[]
     */
    private function capMerge(array $into, array $add): array
    {
        foreach ($add as $w) {
            if (count($into) >= self::BODY_WORD_CAP) {
                break;
            }
            if (!in_array($w, $into, true)) {
                $into[] = $w;
            }
        }

        return $into;
    }

    /**
     * @param string[] $a
     * @param string[] $b
     * @return string[]
     */
    private function union(array $a, array $b): array
    {
        foreach ($b as $w) {
            if (!in_array($w, $a, true)) {
                $a[] = $w;
            }
        }

        return $a;
    }

    /**
     * @param array<string,string[]> $into
     * @param array<string,string[]> $add
     * @return array<string,string[]>
     */
    private function mergeTyped(array $into, array $add): array
    {
        foreach ($add as $name => $subs) {
            $into[$name] = $this->union($into[$name] ?? [], $subs);
        }

        return $into;
    }
}
