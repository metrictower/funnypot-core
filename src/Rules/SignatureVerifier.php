<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Verifies a detached ed25519 signature over the manifest bytes against the trusted key ring.
 * The manifest is the signed root: it pins the tarball's sha256 and every file's sha256, so
 * a signature over the manifest transitively authenticates the whole release. This mirrors
 * the ed25519 primitive funnypot already uses for the SSH host key (Protocol\Ssh\HostKey),
 * just the verify half — sodium_crypto_sign_verify_detached instead of _detached.
 *
 * ext-sodium is a `suggest`, not a `require`, so its absence is a clean, fail-closed refusal
 * (REASON_NO_SODIUM) — never a fatal error, never a bypass.
 */
final class SignatureVerifier
{
    /** @var KeyRing */
    private $keyRing;

    public function __construct(KeyRing $keyRing)
    {
        $this->keyRing = $keyRing;
    }

    public static function fromPackage(): self
    {
        return new self(KeyRing::fromPackage());
    }

    /**
     * @throws RulesUpdateException when no trusted key verifies the signature over $message
     * @return string the key_id that verified (for logging)
     */
    public function verify(string $message, string $signature, ?int $at = null): string
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_NO_SODIUM,
                'ext-sodium is not loaded; refusing to verify a rules signature.'
            );
        }

        $active = $this->keyRing->activeKeys($at);
        if ($active === []) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_NO_TRUSTED_KEY,
                'No signing key is trusted at this time (empty/expired keyring in resources/rules-signing-keys.php).'
            );
        }

        // An ed25519 signature is exactly 64 bytes; a wrong length can make the verify call
        // throw rather than return false, so reject it up front.
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_BAD_SIGNATURE,
                'Signature is not a ' . SODIUM_CRYPTO_SIGN_BYTES . '-byte ed25519 signature.'
            );
        }

        foreach ($active as $key) {
            $ok = false;
            try {
                $ok = sodium_crypto_sign_verify_detached($signature, $message, $key['raw']);
            } catch (\Throwable $e) {
                $ok = false;
            }
            if ($ok) {
                return $key['key_id'];
            }
        }

        throw new RulesUpdateException(
            RulesUpdateException::REASON_BAD_SIGNATURE,
            'Signature did not verify against any trusted key.'
        );
    }
}
