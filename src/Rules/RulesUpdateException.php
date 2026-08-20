<?php

declare(strict_types=1);

namespace Funnypot\Rules;

use RuntimeException;

/**
 * A recoverable update failure. The RulesUpdater catches these internally and turns them
 * into a failed UpdateResult — the library contract is "calling update() can never make
 * things worse than they already were", so the currently-serving rules are never touched.
 * The `reason` is a short machine tag for alerting (see the REASON_* constants).
 */
final class RulesUpdateException extends RuntimeException
{
    public const REASON_LOCKED = 'locked';
    public const REASON_NO_TRANSPORT = 'no-transport';
    public const REASON_FETCH_FAILED = 'fetch-failed';
    public const REASON_NO_SODIUM = 'no-sodium';
    public const REASON_NO_TRUSTED_KEY = 'no-trusted-key';
    public const REASON_BAD_SIGNATURE = 'bad-signature';
    public const REASON_BAD_MANIFEST = 'bad-manifest';
    public const REASON_SHA_MISMATCH = 'sha256-mismatch';
    public const REASON_EXTRACT_FAILED = 'extract-failed';
    public const REASON_NOT_LITERAL = 'not-literal';
    public const REASON_FINGERPRINT_LEAK = 'fingerprint-leak';
    public const REASON_REDOS = 'redos';
    public const REASON_BLINDING = 'coverage-drop';
    public const REASON_DOWNGRADE = 'downgrade';
    public const REASON_SWAP_FAILED = 'swap-failed';
    public const REASON_NOT_RETAINED = 'not-retained';
    public const REASON_CONFIG = 'config';

    /** @var string */
    private $reason;

    public function __construct(string $reason, string $message)
    {
        parent::__construct($message);
        $this->reason = $reason;
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
