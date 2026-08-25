<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

use RuntimeException;

/**
 * Thrown when a candidate compiled artifact is not a pure `return <array literal>;` file.
 * A violation means the bytes could execute something on `require`, so the updater must
 * reject them before they ever reach PhpArrayStore.
 */
final class PhpLiteralViolation extends RuntimeException
{
}
