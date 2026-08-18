<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Default no-op observer.
 */
final class NullObserver implements Observer
{
    public function onDetection(RequestContext $r, Detection $detection): void
    {
    }

    public function shouldRespond(RequestContext $r, Detection $detection): bool
    {
        return true;
    }

    public function onOutcome(RequestContext $r, ?SynthesizedResponse $response, string $reason): void
    {
    }
}
