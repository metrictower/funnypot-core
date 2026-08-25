<?php

declare(strict_types=1);

namespace Funnypot\Core\Response;

/**
 * Rich body + header overrides produced by an endpoint emulator. Headers are merged
 * over the bundle's base headers; the body replaces the minimal one. The composer
 * validates this against the bundle's constraints before using it, so an emulator can
 * be liberal and still never break the matcher guarantee.
 */
final class EmulatedContent
{
    /** @var string */
    public $body;

    /** @var array<string,string> */
    public $headers;

    /** @var int|null status override; null leaves the choice to the caller (the rule's status). */
    public $status;

    /** @param array<string,string> $headers */
    public function __construct(
        string $body,
        array $headers = [],
        ?int $status = null
    ) {
        $this->body = $body;
        $this->headers = $headers;
        $this->status = $status;
    }
}
