<?php

declare(strict_types=1);

namespace Funnypot\Core;

use Funnypot\Core\Reaction\ParamIntent;

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
 * A route handle MAY carry an optional validated ParamIntent (FP-0157): the request-derived query
 * reaction the decorator would append. It is forced null on any non-route kind, serialized only when
 * present (so legacy arrays stay byte-identical), and re-validated on the way back in, so a forged or
 * corrupted intent degrades to the undecorated route response.
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

    /** @var ParamIntent|null query reaction intent; ROUTE handles only, forced null on every other kind */
    public $paramIntent;

    /**
     * @param array<int|string,string> $captures
     */
    public function __construct(string $kind, ?string $key = null, ?string $ruleId = null, array $captures = [], ?ParamIntent $paramIntent = null)
    {
        $this->kind = $kind;
        $this->key = $key;
        $this->ruleId = $ruleId;
        $this->captures = $captures;
        // A query reaction is meaningful only on a route handle; force it null on any other kind so an
        // attack or llm handle can never carry — or serialize — one.
        $this->paramIntent = $kind === self::KIND_ROUTE ? $paramIntent : null;
    }

    public static function route(string $key, ?ParamIntent $paramIntent = null): self
    {
        return new self(self::KIND_ROUTE, $key, null, [], $paramIntent);
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
        $out = [
            'kind' => $this->kind,
            'key' => $this->key,
            'ruleId' => $this->ruleId,
            'captures' => $this->captures,
        ];
        // Emitted ONLY when present, so every legacy handle serializes byte-identically (including
        // Verdict::toArray() and the exact/golden arrays).
        if ($this->paramIntent !== null) {
            $out['paramIntent'] = $this->paramIntent->toArray();
        }

        return $out;
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

        // A paramIntent survives the JSON hop only as a valid array; anything else (a string, a list,
        // an unknown version/kind, a key/kind mismatch, an oversized value) rebuilds as null.
        $intent = null;
        if (isset($data['paramIntent']) && is_array($data['paramIntent'])) {
            $intent = ParamIntent::tryFromArray($data['paramIntent']);
        }

        return new self(
            (string) ($data['kind'] ?? ''),
            isset($data['key']) ? (string) $data['key'] : null,
            isset($data['ruleId']) ? (string) $data['ruleId'] : null,
            $captures,
            $intent
        );
    }
}
