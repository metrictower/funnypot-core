<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

use Funnypot\Core\Template\DirectiveRenderer;

/**
 * Ordered set of endpoint emulators. First one that supports a bundle wins. Apps can
 * supply their own set; default() carries a single data-driven RouteTemplateEmulator that
 * reads the compiled route templates (the built-in endpoint fakes are now data, not code).
 */
final class EmulatorRegistry
{
    /** @var EndpointEmulator[] */
    private $emulators;

    /** @param EndpointEmulator[] $emulators */
    public function __construct(array $emulators)
    {
        $this->emulators = $emulators;
    }

    /**
     * @param int|null $personaSeed per-deploy identity seed; drives {{persona.*}} so the template
     *                              tier shows the same site identity as the app LLM tier. Null keeps
     *                              per-request identity (a missed wiring site degrades, never crashes).
     * @param bool     $promptInjectionSeeding opt-in gate (FP-0239); off ⇒ no injection block, output
     *                              byte-identical to today's. Threaded from Config via Honeypot.
     * @param array<string,string> $beaconCanary operator canary map (e.g. ['beacon' => '<self-beacon url>'])
     *                              wired onto the route tier as the 4th render arg; empty ⇒ no beacon URL.
     */
    public static function default(
        ?int $personaSeed = null,
        bool $promptInjectionSeeding = false,
        array $beaconCanary = []
    ): self {
        return new self([
            new RouteTemplateEmulator(
                RouteTemplateSet::fromPackage(),
                new DirectiveRenderer($personaSeed),
                $promptInjectionSeeding,
                $beaconCanary
            ),
        ]);
    }

    /**
     * @param array<string,mixed> $bundle
     */
    public function find(array $bundle): ?EndpointEmulator
    {
        foreach ($this->emulators as $emulator) {
            if ($emulator->supports($bundle)) {
                return $emulator;
            }
        }

        return null;
    }
}
