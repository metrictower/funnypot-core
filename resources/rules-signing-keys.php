<?php

declare(strict_types=1);

// TRUST ROOT for the funnypot-rules runtime update channel.
//
// The ed25519 PUBLIC keys that RulesUpdater accepts a release signature from. This file
// ships inside the composer package and is the ONLY thing that decides which signer is
// trusted — the public key is NEVER fetched alongside the artifact it verifies. A poisoned
// funnypot-rules repo cannot add its own key here; changing this ring is a normal, reviewed
// funnypot-core PR (the same channel a compromised key would have to bypass to remove
// itself), which is exactly the property a root of trust needs.
//
// Rotation: add the new key_id with a future valid_from well before first use; RulesUpdater
// accepts a signature from ANY key whose [valid_from, valid_until] window covers now(), so
// old and new overlap safely. Retire the old key by setting its valid_until in a later PR.
// Revocation: drop the key_id in a funnypot-core patch release (a `composer update` event,
// deliberately decoupled from the rules channel a compromised key could otherwise spoof).
//
// SHIPPED EMPTY. Until Bob runs dist/funnypot-rules/keygen.sh and commits the printed public
// key here, RulesUpdater has no trusted signer and every update() fails closed (the bundled
// rules keep serving — see RulesLocator). Each entry:
//
//   ['key_id' => '2026-01', 'public_key' => '<base64 32-byte ed25519 public key>',
//    'valid_from' => '2026-01-01', 'valid_until' => null]

return [
    'keys' => [
        // ['key_id' => '2026-01', 'public_key' => 'BASE64_PUBLIC_KEY_HERE',
        //  'valid_from' => '2026-01-01', 'valid_until' => null],
    ],
];
