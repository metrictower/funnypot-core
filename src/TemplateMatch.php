<?php

declare(strict_types=1);

namespace Funnypot\Core;

/**
 * One nuclei template that an incoming request was probing for.
 */
final class TemplateMatch
{
    /** @var string */
    public $id;

    /** @var string */
    public $severity;

    /** @var string[] */
    public $tags;

    /** @var string */
    public $name;

    /** @param string[] $tags */
    public function __construct(
        string $id,
        string $severity,
        array $tags,
        string $name = ''
    ) {
        $this->id = $id;
        $this->severity = $severity;
        $this->tags = $tags;
        $this->name = $name;
    }
}
