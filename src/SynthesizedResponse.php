<?php

declare(strict_types=1);

namespace Funnypot\Core;

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

    /**
     * The winning decoy handle (route key / attack rule id) that produced this response, surfaced
     * for the app's debug tooling. INTERNAL ONLY: never a served string. ResponseEmitter writes
     * only $headers + $body, so this stays inert — a leaked decoy id would fingerprint the honeypot.
     * Null on the position-blind synthesize() port; set by the respond() facade.
     *
     * @var FakeHandle|null
     */
    public $servedBy;

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
        $this->servedBy = null;
    }
}
