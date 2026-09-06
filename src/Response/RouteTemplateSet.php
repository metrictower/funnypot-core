<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

use Funnypot\Core\Rules\RulesLocator;

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
    /** @var array<int,array<string,mixed>> compiled route rules, priority-ordered */
    private $rules;

    /** @param array<int,array<string,mixed>> $rules compiled route rules, priority-ordered */
    public function __construct(array $rules)
    {
        $this->rules = $rules;
    }

    public static function fromFile(string $path): self
    {
        $rules = is_file($path) ? require $path : [];

        return new self(is_array($rules) ? $rules : []);
    }

    /**
     * Build against the route rules — a RulesUpdater-managed copy under the configured data
     * dir when present, else the copy compiled into the package (RulesLocator decides).
     */
    public static function fromPackage(): self
    {
        return self::fromFile(RulesLocator::resolve('funnypot-routes.php'));
    }

    /**
     * First rule whose selector recognises this bundle, or null. Selector is an OR across
     * three axes (mirroring the old supports() variants):
     *   - template_needle: bundle pid === needle, OR needle is a substring of any t[] id
     *   - pid:             exact bundle pid match
     *   - body_word_contains: any bw word contains the needle (the ssh "PRIVATE KEY" axis)
     *
     * A rule may additionally declare `match.route_key`: a conjunctive GUARD (never a fourth OR
     * axis). When present, the resolved route key must equal one entry exactly AND one of the three
     * axes must still match. $routeKey is the store key Honeypot resolved before synthesis ('<METHOD>
     * <path>'); null (a direct unit test / embedded call) can never satisfy a guarded rule, so
     * unguarded rules keep their first-match behaviour and guarded ones simply decline.
     *
     * @param array<string,mixed> $bundle
     * @return array<string,mixed>|null
     */
    public function findRule(array $bundle, ?string $routeKey = null): ?array
    {
        foreach ($this->rules as $rule) {
            if ($this->selects($bundle, (array) ($rule['match'] ?? []), $routeKey)) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * @param array<string,mixed> $bundle
     * @param array<string,mixed> $match
     */
    private function selects(array $bundle, array $match, ?string $routeKey): bool
    {
        // route_key is a conjunctive guard consulted first: a rule that declares it only applies to
        // an exact resolved key, so a wrong or null key declines before any body/pid axis is read.
        if (isset($match['route_key'])
            && ($routeKey === null || !in_array($routeKey, (array) $match['route_key'], true))) {
            return false;
        }

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
