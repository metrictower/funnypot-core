<?php

declare(strict_types=1);

namespace Funnypot\Core\Reaction;

/**
 * The code-owned halves of a rendered reaction, with the SINGLE display slot between them. The
 * attacker value is NEVER inside $before/$after — the decorator inserts it (entity- or byte-encoded)
 * between the halves. This split is what lets the fingerprint guard scan only code-owned bytes
 * ($before/$after), never the reflected value, so no differential oracle can form.
 *
 * $usesValue === false means the family displays no value at all: $after is '' and the decorator emits
 * $before alone (only the debug-view family does this).
 *
 * 7.3-clean: classic constructor, docblocked untyped properties, final.
 */
final class ReactionFragment
{
    /** @var string code-owned bytes before the display slot */
    public $before;

    /** @var string code-owned bytes after the display slot ('' when $usesValue is false) */
    public $after;

    /** @var bool whether the display slot carries the attacker value */
    public $usesValue;

    public function __construct(string $before, string $after, bool $usesValue)
    {
        $this->before = $before;
        $this->after = $usesValue ? $after : '';
        $this->usesValue = $usesValue;
    }
}
