<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Gate B outcome for one template: either an invertible {@see SatisfyPlan} (IN) or a
 * fold-OUT reason for the skipped.json audit.
 */
final class ClassifiedTemplate
{
    /** @var bool */
    public $in;

    /** @var SatisfyPlan|null */
    public $plan;

    /** @var string */
    public $reason;

    private function __construct(
        bool $in,
        ?SatisfyPlan $plan,
        string $reason
    ) {
        $this->in = $in;
        $this->plan = $plan;
        $this->reason = $reason;
    }

    public static function in(SatisfyPlan $plan): self
    {
        return new self(true, $plan, '');
    }

    public static function out(string $reason): self
    {
        return new self(false, null, $reason);
    }
}
