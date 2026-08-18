<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * One nuclei template that an incoming request was probing for.
 */
final class TemplateMatch
{
    /** @param string[] $tags */
    public function __construct(
        public string $id,
        public string $severity,
        public array $tags,
        public string $name = ''
    ) {
    }
}
