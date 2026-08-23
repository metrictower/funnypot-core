<?php

declare(strict_types=1);

namespace Funnypot\Response;

use Funnypot\Template\DirectiveRenderer;

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
     */
    public static function default(?int $personaSeed = null): self
    {
        return new self([
            new RouteTemplateEmulator(RouteTemplateSet::fromPackage(), new DirectiveRenderer($personaSeed)),
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
