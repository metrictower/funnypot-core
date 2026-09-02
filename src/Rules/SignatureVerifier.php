<?php

declare(strict_types=1);

namespace Funnypot\Core\Rules;

/**
 * Verifies a detached ed25519 signature over a CONTEXT-PREFIXED, ROLE-SCOPED document against the
 * trusted key ring. The manifest is the signed root: it pins the tarball's sha256 and every file's
 * sha256, so a signature over the manifest transitively authenticates the whole release. This
 * mirrors the ed25519 primitive funnypot already uses for the SSH host key (Protocol\Ssh\HostKey),
 * just the verify half — sodium_crypto_sign_verify_detached.
 *
 * DOMAIN SEPARATION: the signed message is `$context . $documentBytes`, never the raw bytes. A
 * `channels.json` signature can therefore never verify as a `<version>.manifest.json` signature (or
 * vice-versa) even if the two byte-strings ever collided — the context prefix is different. The
 * document bytes on the wire are unchanged; only the signed message is prefixed.
 *
 * ROLE SEPARATION: verification is scoped to a signer role (`ROLE_CHANNELS` / `ROLE_RELEASE`) and
 * only key-ring entries that declare that role are offered. One stolen CI secret can then move the
 * pointer among already-signed releases OR sign a release nobody points to, but not both.
 *
 * ext-sodium is a `suggest`, not a `require`, so its absence is a clean, fail-closed refusal
 * (REASON_NO_SODIUM) — never a fatal error, never a bypass.
 */
final class SignatureVerifier
{
    /**
     * Domain-separation context prefixes. The trailing "\n" keeps the prefix unambiguous — a signed
     * message can never be read as document JSON that merely begins with the prefix text. The `v2`
     * segment is the update-channel envelope schema (SchemaVersion::RELEASE_CURRENT).
     */
    public const CONTEXT_CHANNELS = "funnypot-rules:channels:v2\n";
    public const CONTEXT_MANIFEST = "funnypot-rules:manifest:v2\n";

    public const ROLE_CHANNELS = 'channels';
    public const ROLE_RELEASE = 'release';

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
     * Verify $signature over `$context . $message` against the keys that hold $role at time $at.
     *
     * @throws RulesUpdateException when no trusted key verifies the signature
     * @return string the key_id that verified (for logging)
     */
    public function verify(string $message, string $signature, string $context, string $role, ?int $at = null): string
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_NO_SODIUM,
                'ext-sodium is not loaded; refusing to verify a rules signature.'
            );
        }

        $active = $this->keyRing->activeKeys($at, $role);
        if ($active === []) {
            throw new RulesUpdateException(
                RulesUpdateException::REASON_NO_TRUSTED_KEY,
                "No signing key is trusted for role '{$role}' at this time (empty/expired/role-mismatched keyring in resources/rules-signing-keys.php)."
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

        $signed = $context . $message;
        foreach ($active as $key) {
            $ok = false;
            try {
                $ok = sodium_crypto_sign_verify_detached($signature, $signed, $key['raw']);
            } catch (\Throwable $e) {
                $ok = false;
            }
            if ($ok) {
                return $key['key_id'];
            }
        }

        throw new RulesUpdateException(
            RulesUpdateException::REASON_BAD_SIGNATURE,
            "Signature did not verify against any trusted '{$role}' key."
        );
    }
}
