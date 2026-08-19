#!/usr/bin/env bash
#
# License-compatibility CI gate.
#
# Given a fetched upstream source dir, resolve its license to an SPDX id and fail the build
# unless it is on the allow-list (resources/ALLOWED-LICENSES.txt). On success the license text
# is copied into the PR diff, so a human reviewer sees the actual terms — not just a boolean —
# and any wording/clause change upstream shows up in the diff. Mirrors, and automates as a hard
# stop, the license-provenance discipline funnypot already applies by hand for nuclei-templates.
#
#   scripts/ci/check-license.sh <source-dir> <dest-license-path>
#
set -euo pipefail

SRC="${1:-}"
DEST="${2:-}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ALLOW="$ROOT/resources/ALLOWED-LICENSES.txt"

if [ -z "$SRC" ] || [ -z "$DEST" ]; then
  echo "usage: check-license.sh <source-dir> <dest-license-path>" >&2
  exit 2
fi
if [ ! -d "$SRC" ]; then
  echo "FAIL: source dir not found: $SRC" >&2
  exit 1
fi

# Locate the license file (GitHub-style names).
LICENSE_FILE=""
for name in LICENSE LICENSE.md LICENSE.txt COPYING COPYING.md; do
  if [ -f "$SRC/$name" ]; then
    LICENSE_FILE="$SRC/$name"
    break
  fi
done
if [ -z "$LICENSE_FILE" ]; then
  echo "FAIL: no LICENSE/COPYING file found in $SRC" >&2
  exit 1
fi

# Resolve an SPDX id from the text (order matters — most specific marker first).
SPDX=""
if grep -qi "Apache License" "$LICENSE_FILE" && grep -qi "Version 2.0" "$LICENSE_FILE"; then
  SPDX="Apache-2.0"
elif grep -qi "GNU GENERAL PUBLIC LICENSE" "$LICENSE_FILE"; then
  SPDX="GPL"   # deliberately un-allow-listed; copyleft is incompatible with MIT redistribution
elif grep -qi "Redistribution and use in source and binary" "$LICENSE_FILE"; then
  if grep -qi "neither the name" "$LICENSE_FILE"; then
    SPDX="BSD-3-Clause"
  else
    SPDX="BSD-2-Clause"
  fi
elif grep -qi "CC0" "$LICENSE_FILE" || grep -qi "Creative Commons Zero" "$LICENSE_FILE"; then
  SPDX="CC0-1.0"
elif grep -qi "Permission is hereby granted, free of charge" "$LICENSE_FILE"; then
  SPDX="MIT"
fi

if [ -z "$SPDX" ]; then
  echo "FAIL: could not resolve an SPDX id from $LICENSE_FILE" >&2
  exit 1
fi

if ! grep -qxF "$SPDX" "$ALLOW"; then
  echo "::error::license '$SPDX' from $LICENSE_FILE is not on the allow-list ($ALLOW)" >&2
  echo "FAIL: license $SPDX is not allow-listed" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
cp "$LICENSE_FILE" "$DEST"
echo "OK: upstream license resolved to $SPDX (allow-listed); text copied to $DEST"
exit 0
