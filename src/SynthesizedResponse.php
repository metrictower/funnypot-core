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
    /** @param array<string,string> $headers */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
        public Detection $satisfies
    ) {
    }
}
