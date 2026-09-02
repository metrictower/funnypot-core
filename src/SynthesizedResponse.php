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

    /**
     * @var array<string,string|string[]> A value may be a plain string (one header line) or a list
     * of strings (several lines under one name) — so a honeytoken Set-Cookie and a session
     * Set-Cookie can coexist. The pipe carries either; every current producer emits plain strings,
     * so existing output is byte-identical.
     */
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

    /**
     * Microseconds an emitter/adapter should pause before writing this response — the optional
     * tarpit delay, carried as metadata so it is applied at the transport edge, never by the core
     * (an in-core usleep blocks the host worker pool). INTERNAL ONLY, exactly like $servedBy: never
     * serialized into served bytes (ResponseEmitter writes only $headers + $body), so it is
     * fingerprint-inert by construction. 0 on the position-blind synthesize() port and by default;
     * set only by the respond() facade from Config::serveDelayMicros().
     *
     * @var int
     */
    public $delayMicros = 0;

    /** @param array<string,string|string[]> $headers */
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
