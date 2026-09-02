<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * The template / rule-artifact schema version this engine understands. The compiler rejects a template
 * whose `version:` exceeds this — a fail-safe so an older deployed engine never mis-parses a newer-format
 * template rather than choking on it. Bump `CURRENT` ONLY on a backward-incompatible change to the
 * template DSL.
 *
 * `RELEASE_CURRENT` is a SEPARATE axis: the highest funnypot-rules update-channel envelope
 * (`<version>.manifest.json` / `channels.json`) `schema` this engine's RulesUpdater accepts. It is
 * decoupled from the template DSL `CURRENT` on purpose — the update-channel format (signed freshness
 * windows + context/role-separated signatures, schema 2) evolved without any change to the template
 * DSL (still schema 1). RulesUpdater refuses an envelope whose `schema` exceeds `RELEASE_CURRENT` so an
 * older engine keeps serving last-good rather than mis-verifying a newer envelope. Bump
 * `RELEASE_CURRENT` when the signed update-channel format changes.
 */
final class SchemaVersion
{
    public const CURRENT = 1;

    public const RELEASE_CURRENT = 2;
}
