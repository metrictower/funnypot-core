<?php

declare(strict_types=1);

namespace Funnypot\Rules;

/**
 * The outcome of an update()/rollback() call. A value object — never throws, safe to log.
 * `changed` is true only when `current` was actually repointed; a no-op "already current"
 * is success with changed=false.
 */
final class UpdateResult
{
    public bool $success;
    public bool $changed;
    /** Short machine tag: 'updated', 'already-current', 'rolled-back', or a REASON_* on failure. */
    public string $status;
    public ?string $fromVersion;
    public ?string $toVersion;
    public string $message;

    public function __construct(
        bool $success,
        bool $changed,
        string $status,
        ?string $fromVersion,
        ?string $toVersion,
        string $message
    ) {
        $this->success = $success;
        $this->changed = $changed;
        $this->status = $status;
        $this->fromVersion = $fromVersion;
        $this->toVersion = $toVersion;
        $this->message = $message;
    }

    public static function updated(?string $from, string $to): self
    {
        return new self(true, true, 'updated', $from, $to, "Updated rules {$from} -> {$to}.");
    }

    public static function noop(?string $current): self
    {
        return new self(true, false, 'already-current', $current, $current, 'Already at the target version.');
    }

    public static function rolledBack(?string $from, string $to): self
    {
        return new self(true, true, 'rolled-back', $from, $to, "Rolled back rules {$from} -> {$to}.");
    }

    public static function failed(string $reason, string $message, ?string $current = null): self
    {
        return new self(false, false, $reason, $current, $current, $message);
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return [
            'success' => $this->success,
            'changed' => $this->changed,
            'status' => $this->status,
            'from' => $this->fromVersion,
            'to' => $this->toVersion,
            'message' => $this->message,
        ];
    }
}
