<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * Ordered set of endpoint emulators. First one that supports a bundle wins. Apps can
 * supply their own set; default() carries a single data-driven RouteTemplateEmulator that
 * reads the compiled route templates (the built-in endpoint fakes are now data, not code).
 */
final class EmulatorRegistry
{
    /** @var EndpointEmulator[] */
    private array $emulators;

    /** @param EndpointEmulator[] $emulators */
    public function __construct(array $emulators)
    {
        $this->emulators = $emulators;
    }

    public static function default(): self
    {
        return new self([
            new RouteTemplateEmulator(RouteTemplateSet::fromPackage()),
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
