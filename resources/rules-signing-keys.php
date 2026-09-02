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
// ROLE SEPARATION (required): each entry declares `roles` — a list of the signer roles it may
// verify. There are two: 'release' (signs a <version>.manifest.json, the release root) and
// 'channels' (signs channels.json, the version pointer). They are held by SEPARATE CI secrets so
// one stolen secret can move the pointer among already-signed releases OR sign a release nobody
// points to, but not both. A dual-role key is possible but must say so explicitly
// (`'roles' => ['release', 'channels']`). An entry WITHOUT a `roles` list matches NO role and is
// never offered to the verifier (fail-closed).
//
// DATE FORMATS (strict, fail-closed): valid_from / valid_until are `Y-m-d` (midnight UTC) or a
// full RFC3339 timestamp, or null for "unbounded". A present-but-unparseable window (a typo like
// "2026-13-45") DROPS the whole key rather than being ignored — a trust-root typo can only shrink
// trust, never extend it (KeyRing parses strictly, NOT via lenient strtotime).
//
// SHIPPED EMPTY. Until Bob runs dist/funnypot-rules/keygen.sh and commits the printed public
// keys here, RulesUpdater has no trusted signer and every update() fails closed (the bundled
// rules keep serving — see RulesLocator). Each entry:
//
//   ['key_id' => '2026-01-release', 'public_key' => '<base64 32-byte ed25519 public key>',
//    'valid_from' => '2026-01-01', 'valid_until' => null, 'roles' => ['release']]

return [
    'keys' => [
        // ['key_id' => '2026-01-release', 'public_key' => 'BASE64_RELEASE_PUBLIC_KEY_HERE',
        //  'valid_from' => '2026-01-01', 'valid_until' => null, 'roles' => ['release']],
        // ['key_id' => '2026-01-channels', 'public_key' => 'BASE64_CHANNELS_PUBLIC_KEY_HERE',
        //  'valid_from' => '2026-01-01', 'valid_until' => null, 'roles' => ['channels']],
    ],
];
