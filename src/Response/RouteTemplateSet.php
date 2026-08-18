<?php

declare(strict_types=1);

namespace Funnypot\Response;

/**
 * The compiled route-template rules, priority-ordered, consumed by RouteTemplateEmulator.
 * findRule() reproduces the old per-emulator supports() logic as data: first rule (by
 * compile-time priority) whose selector matches the served bundle wins — the same
 * first-match-wins ordering EmulatorRegistry::default() gave the 11 hand-coded classes.
 *
 * Runtime is PHP-only: rules are a frozen PHP array (compiled from YAML at build time).
 */
final class RouteTemplateSet
{
    /** @param array<int,array<string,mixed>> $rules compiled route rules, priority-ordered */
    public function __construct(private array $rules)
    {
    }

    public static function fromFile(string $path): self
    {
        $rules = is_file($path) ? require $path : [];

        return new self(is_array($rules) ? $rules : []);
    }

    /** Build against the route rules compiled into the package. */
    public static function fromPackage(): self
    {
        return self::fromFile(dirname(__DIR__, 2) . '/resources/compiled/funnypot-routes.php');
    }

    /**
     * First rule whose selector recognises this bundle, or null. Selector is an OR across
     * three axes (mirroring the old supports() variants):
     *   - template_needle: bundle pid === needle, OR needle is a substring of any t[] id
     *   - pid:             exact bundle pid match
     *   - body_word_contains: any bw word contains the needle (the ssh "PRIVATE KEY" axis)
     *
     * @param array<string,mixed> $bundle
     * @return array<string,mixed>|null
     */
    public function findRule(array $bundle): ?array
    {
        foreach ($this->rules as $rule) {
            if ($this->selects($bundle, (array) ($rule['match'] ?? []))) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * @param array<string,mixed> $bundle
     * @param array<string,mixed> $match
     */
    private function selects(array $bundle, array $match): bool
    {
        $pid = (string) ($bundle['pid'] ?? '');
        $ids = array_map('strval', (array) ($bundle['t'] ?? []));

        foreach ((array) ($match['template_needle'] ?? []) as $needle) {
            $needle = (string) $needle;
            if ($pid === $needle) {
                return true;
            }
            foreach ($ids as $id) {
                if (strpos($id, $needle) !== false) {
                    return true;
                }
            }
        }

        foreach ((array) ($match['pid'] ?? []) as $needle) {
            if ($pid === (string) $needle) {
                return true;
            }
        }

        foreach ((array) ($match['body_word_contains'] ?? []) as $needle) {
            $needle = (string) $needle;
            foreach ((array) ($bundle['bw'] ?? []) as $word) {
                if (strpos((string) $word, $needle) !== false) {
                    return true;
                }
            }
        }

        return false;
    }
}
