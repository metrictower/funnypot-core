<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

use Funnypot\Core\Template\DirectiveRenderer;

/**
 * A built-in writer for a binary route body that cannot be authored as static bytes because it must
 * carry the deploy's seeded persona (a heap dump planting this host's credentials). Selected by a
 * route template's `response.binary_generator` — a closed ID validated at compile time against
 * BinaryBodyGeneratorRegistry::IDS — never by class name or callback, so a rule artifact can only
 * ever pick a generator that ships with the engine.
 *
 * Implementations are pure functions of the renderer's seeded directives and $seed: no I/O, no
 * clock, no request data, no CSPRNG. Return null to decline; the emulator then serves nothing and
 * the host falls back to its ordinary 404. The emulator, not the generator, enforces the non-empty
 * and size-ceiling contract.
 */
interface BinaryBodyGenerator
{
    public function generate(DirectiveRenderer $renderer, int $seed): ?string;
}
