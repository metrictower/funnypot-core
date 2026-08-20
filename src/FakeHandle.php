<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * Opaque, serializable pointer from a Verdict to what synthesize() would build — never
 * a rendered response or a bundle blob (two-phase design §2.1).
 *
 * Kinds:
 *  - route:  a resolved nuclei routing key ('<METHOD> <normalized-path>').
 *  - attack: a matched attack rule id, plus the request captures the render reflects
 *            ({{match.N}}). The captures ride here because synthesize() gets no request —
 *            they are the request-derived data needed to rebuild the fake byte-identically.
 *  - llm:    reserved. The app-side LLM fake is a host-injected synthesizer named by this
 *            kind; core never builds it (design §1 tension).
 *
 * 7.3-clean: classic constructor, docblocked untyped properties.
 */
final class FakeHandle
{
    public const KIND_ROUTE = 'route';
    public const KIND_ATTACK = 'attack';
    public const KIND_LLM = 'llm';

    /** @var string one of the KIND_* constants */
    public $kind;

    /** @var string|null route routing key */
    public $key;

    /** @var string|null attack rule id */
    public $ruleId;

    /** @var array<int|string,string> attack render captures ({{match.N}}); [] otherwise */
    public $captures;

    /**
     * @param array<int|string,string> $captures
     */
    public function __construct(string $kind, ?string $key = null, ?string $ruleId = null, array $captures = [])
    {
        $this->kind = $kind;
        $this->key = $key;
        $this->ruleId = $ruleId;
        $this->captures = $captures;
    }

    public static function route(string $key): self
    {
        return new self(self::KIND_ROUTE, $key, null, []);
    }

    /**
     * @param array<int|string,string> $captures
     */
    public static function attack(string $ruleId, array $captures = []): self
    {
        return new self(self::KIND_ATTACK, null, $ruleId, $captures);
    }

    /**
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        return [
            'kind' => $this->kind,
            'key' => $this->key,
            'ruleId' => $this->ruleId,
            'captures' => $this->captures,
        ];
    }

    /**
     * @param array<string,mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $captures = [];
        foreach ((array) ($data['captures'] ?? []) as $k => $v) {
            $captures[$k] = (string) $v;
        }

        return new self(
            (string) ($data['kind'] ?? ''),
            isset($data['key']) ? (string) $data['key'] : null,
            isset($data['ruleId']) ? (string) $data['ruleId'] : null,
            $captures
        );
    }
}
