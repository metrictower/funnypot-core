<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * The template / rule-artifact schema version this engine understands. The compiler rejects a template
 * whose `version:` exceeds this, and RulesUpdater refuses a signed release whose manifest `schema`
 * exceeds it — a fail-safe so an older deployed engine never mis-parses a newer-format release rather
 * than choking on it. Bump ONLY on a backward-incompatible change to the template DSL.
 */
final class SchemaVersion
{
    public const CURRENT = 1;
}
