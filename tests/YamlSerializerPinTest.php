<?php

declare(strict_types=1);

namespace Funnypot\Core\Tests;

use PHPUnit\Framework\TestCase;

/**
 * The compile-time YAML serializer is part of the generated-artifact ABI. `compile-ai` serializes
 * committed compiler inputs with `symfony/yaml`, so the serializer *version* — not just its PHP API —
 * helps define the generated YAML bytes, the reproducible source_tree stamp and the compiled index. A
 * formatter change in a later 5.4 patch would drift those artifacts on an otherwise unrelated change,
 * so the dependency is pinned to an exact version. This guard fails if the constraint ever floats
 * again; bumping it is a deliberate artifact migration — change EXPECTED_YAML_VERSION in the same
 * commit that regenerates and reviews every compiled output.
 */
final class YamlSerializerPinTest extends TestCase
{
    /** The exact symfony/yaml the committed generated YAML/PHP artifacts were serialized with. */
    private const EXPECTED_YAML_VERSION = '5.4.53';

    public function test_require_dev_pins_symfony_yaml_to_the_exact_serializer_version(): void
    {
        $composer = $this->composerJson();
        self::assertArrayHasKey('require-dev', $composer);
        self::assertArrayHasKey('symfony/yaml', $composer['require-dev'], 'symfony/yaml must stay a require-dev dependency');

        $constraint = (string) $composer['require-dev']['symfony/yaml'];
        self::assertSame(
            self::EXPECTED_YAML_VERSION,
            $constraint,
            'symfony/yaml must be pinned to the exact serializer version that produced the committed artifacts'
        );
        self::assertTrue(
            self::isExactVersion($constraint),
            'symfony/yaml constraint must be an exact version, not a floating/range form'
        );
    }

    public function test_the_pin_keeps_symfony_yaml_off_the_runtime_floor(): void
    {
        // The pin must not raise the package's runtime floor: symfony/yaml is require-dev only and
        // v5.4.53 declares php >=7.2.5, below core's >=7.3. Assert the floors stay put so a future
        // edit that also moved them would be caught here.
        $composer = $this->composerJson();
        self::assertSame('>=7.3', $composer['require']['php'] ?? null);
        self::assertSame('7.3.0', $composer['config']['platform']['php'] ?? null);
        self::assertArrayNotHasKey('symfony/yaml', (array) ($composer['require'] ?? []), 'symfony/yaml must not move into runtime require');
    }

    public function test_exact_version_detector_rejects_floating_constraints(): void
    {
        // The invariant the pin defends: only a bare X.Y.Z is an exact serializer pin. Every
        // floating/range/stability form must be rejected so the constraint cannot silently move.
        foreach (['^5.4', '~5.4.53', '5.4.*', '>=5.4', '5.4', '5.4.53 || ^6.0', 'dev-main', 'v5.4.53', '*'] as $floating) {
            self::assertFalse(self::isExactVersion($floating), "'{$floating}' must not count as an exact pin");
        }
        foreach (['5.4.53', '6.0.0', '1.2.3'] as $exact) {
            self::assertTrue(self::isExactVersion($exact), "'{$exact}' must count as an exact pin");
        }
    }

    /** An exact pin is a bare three-part version with no operator, wildcard, range or stability flag. */
    private static function isExactVersion(string $constraint): bool
    {
        return (bool) preg_match('/^\d+\.\d+\.\d+$/', $constraint);
    }

    /** @return array<string,mixed> */
    private function composerJson(): array
    {
        $path = __DIR__ . '/../composer.json';
        self::assertFileExists($path);
        $decoded = json_decode((string) file_get_contents($path), true);
        self::assertIsArray($decoded, 'composer.json must be valid JSON');

        return $decoded;
    }
}
