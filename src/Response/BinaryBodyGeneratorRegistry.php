<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

/**
 * The closed map of binary body generators, keyed by the ID a route template names in
 * `response.binary_generator`. IDS is the single source of truth the compiler lints against, so a
 * YAML document can select only a generator that exists here — it can never supply a class name,
 * a callback or arguments (the rules-update channel ships compiled rules as require'd PHP, and this
 * keeps a generator rule pure data).
 */
final class BinaryBodyGeneratorRegistry
{
    /** SpringHprofGenerator — a bounded HotSpot HPROF heap dump planting the persona's secrets. */
    public const SPRING_HPROF_V1 = 'spring_hprof_v1';

    /** Every ID a route template may name. Append-only; an ID is a public rule-artifact contract. */
    public const IDS = [self::SPRING_HPROF_V1];

    /** @var array<string,BinaryBodyGenerator> */
    private $generators;

    /** @param array<string,BinaryBodyGenerator> $generators keyed by ID */
    public function __construct(array $generators)
    {
        $this->generators = $generators;
    }

    /** The production registry: one built-in instance per ID in IDS. */
    public static function default(): self
    {
        return new self([
            self::SPRING_HPROF_V1 => new SpringHprofGenerator(),
        ]);
    }

    public function find(string $id): ?BinaryBodyGenerator
    {
        return $this->generators[$id] ?? null;
    }
}
