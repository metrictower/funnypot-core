<?php

declare(strict_types=1);

namespace Funnypot\Compiler;

/**
 * Screen A2 — dynamic `{{…}}` literals (highest-priority classifier screen).
 *
 * Any word/regex/dsl literal is run through here before it can become a constraint.
 * `{{Hostname}}`/`{{Host}}` resolve to values the synthesizer controls, so a literal
 * built only from those (plus fixed text) is kept. Every other template variable
 * (`{{randstr}}`, `{{md5(...)}}`, `{{interactsh-url}}`, an extracted `{{result}}`) is
 * resolved by nuclei at scan time to a value we cannot predict, so the literal is dead
 * on the wire and its matcher must fold OUT.
 */
final class DynamicLiteralScreen
{
    /** Variables the synthesizer can resolve at respond time. */
    private const RESOLVABLE = ['hostname', 'host'];

    /**
     * True when the literal can be materialized at compile/respond time.
     */
    public static function isResolvable(string $literal): bool
    {
        if (strpos($literal, '{{') === false) {
            return true;
        }

        if (!preg_match_all('/\{\{(.*?)\}\}/s', $literal, $m)) {
            // A stray unbalanced "{{" — treat as unresolvable to stay safe.
            return false;
        }

        foreach ($m[1] as $token) {
            $head = strtolower(trim($token));
            if (!in_array($head, self::RESOLVABLE, true)) {
                return false;
            }
        }

        return true;
    }
}
