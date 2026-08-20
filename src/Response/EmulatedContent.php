<?php

declare(strict_types=1);

namespace Funnypot\Response;

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

    /** @param array<string,string> $headers */
    public function __construct(
        string $body,
        array $headers = []
    ) {
        $this->body = $body;
        $this->headers = $headers;
    }
}
