#!/usr/bin/env bash
#
# Generate the ed25519 signing keypair for the funnypot-rules channel.
#
# Prints TWO things:
#   1. the PUBLIC key — commit this into funnypot-core's resources/rules-signing-keys.php
#      (the trust root the updater verifies against; it is NEVER fetched at runtime).
#   2. the SECRET key (base64) — store this as the FUNNYPOT_RULES_SIGNING_KEY secret on the
#      funnypot-core repo. It NEVER touches a laptop after generation, is never committed, and
#      only the publish-rules.yml workflow ever reads it.
#
# Requires the PHP sodium extension (already a funnypot-core `suggest`).
#
#   bash dist/funnypot-rules/keygen.sh [key-id]
#
set -euo pipefail

KEY_ID="${1:-$(date -u +%Y-%m)}"
VALID_FROM="$(date -u +%Y-%m-%d)"

php -r '
$pair   = sodium_crypto_sign_keypair();
$secret = sodium_crypto_sign_secretkey($pair);   // 64 bytes
$public = sodium_crypto_sign_publickey($pair);   // 32 bytes
fwrite(STDOUT, base64_encode($public) . "\n");
fwrite(STDERR, base64_encode($secret) . "\n");
' >/tmp/funnypot-rules.pub 2>/tmp/funnypot-rules.sec

PUB="$(cat /tmp/funnypot-rules.pub)"
SEC="$(cat /tmp/funnypot-rules.sec)"
rm -f /tmp/funnypot-rules.pub /tmp/funnypot-rules.sec

cat <<EOF
================================================================================
funnypot-rules signing keypair — key_id: ${KEY_ID}
================================================================================

1) PUBLIC KEY — add this entry to funnypot-core resources/rules-signing-keys.php
   (inside the 'keys' array), commit it via a normal reviewed PR:

    ['key_id' => '${KEY_ID}', 'public_key' => '${PUB}',
     'valid_from' => '${VALID_FROM}', 'valid_until' => null],

   Also set the repo variable FUNNYPOT_RULES_KEY_ID = ${KEY_ID} on funnypot-core
   so the publisher stamps the matching key_id into each manifest.

2) SECRET KEY — store as the FUNNYPOT_RULES_SIGNING_KEY secret on the
   funnypot-core repo (Settings -> Secrets -> Actions). Do NOT commit it anywhere:

    ${SEC}

   Shred your terminal scrollback after copying it.

Rotation: run this again with a new key-id, commit the new public key with a
future valid_from, keep the old key valid (valid_until: null) until nothing
signs with it, then retire the old key with a valid_until in a later PR.
================================================================================
EOF
