<?php
declare(strict_types=1);
namespace Funnypot\Core\Support\Chrome;

/** The only HTML-escape primitive the shell/skins use. Every model-supplied value passes through
 *  here before it reaches a text or attribute sink — the load-bearing anti-injection control. */
final class Esc
{
    public static function text(string $v): string
    {
        return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function attr(string $v): string
    {
        return htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
