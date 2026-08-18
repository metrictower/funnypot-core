<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Gate B outcome for one template: either an invertible {@see SatisfyPlan} (IN) or a
 * fold-OUT reason for the skipped.json audit.
 */
final class ClassifiedTemplate
{
    private function __construct(
        public bool $in,
        public ?SatisfyPlan $plan,
        public string $reason
    ) {
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
