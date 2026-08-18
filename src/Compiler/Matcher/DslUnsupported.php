<?php

declare(strict_types=1);

namespace Funnypot\Compiler\Matcher;

use RuntimeException;

/**
 * Thrown the moment a dsl expression leaves the invertible whitelist, carrying the
 * fold-OUT reason. Any unknown token collapses the whole matcher to OUT.
 */
final class DslUnsupported extends RuntimeException
{
}
