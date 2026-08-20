<?php

declare(strict_types=1);

namespace Funnypot;

/**
 * A fake response built to satisfy the matched template(s). Emitted only in
 * respond mode (Phase 4+). $satisfies records the subset actually served, for
 * the app's logging.
 */
final class SynthesizedResponse
{
    /** @var int */
    public $status;

    /** @var array<string,string> */
    public $headers;

    /** @var string */
    public $body;

    /** @var Detection */
    public $satisfies;

    /** @param array<string,string> $headers */
    public function __construct(
        int $status,
        array $headers,
        string $body,
        Detection $satisfies
    ) {
        $this->status = $status;
        $this->headers = $headers;
        $this->body = $body;
        $this->satisfies = $satisfies;
    }
}
