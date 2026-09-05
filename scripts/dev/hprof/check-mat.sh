#!/usr/bin/env bash
#
# check-mat.sh — opt-in interop harness for the spring_hprof_v1 heap-dump decoy.
#
# Writes the generated fixture for one persona seed, proves `strings -a` recovers every planted
# secret, and — only when a preinstalled Eclipse MAT is named — parses the file with MAT's headless
# parser and fails if MAT rejects it. Downloads and installs nothing: the MAT half runs where an
# operator/CI image already ships MAT (`--mat=/path/to/mat`, or $MAT_HOME). The PHPUnit suite
# carries the strict in-repo parser; this adds the one independent parser. Run from anywhere.
#
#   scripts/dev/hprof/check-mat.sh [--seed=<material>] [--mat=<mat-dir>] [--out=<dir>]

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SEED="fixture"
MAT="${MAT_HOME:-}"
OUT="$(mktemp -d)"
for arg in "$@"; do
    case "$arg" in
        --seed=*) SEED="${arg#--seed=}" ;;
        --mat=*)  MAT="${arg#--mat=}" ;;
        --out=*)  OUT="${arg#--out=}" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done
mkdir -p "$OUT"
FIXTURE="$OUT/heapdump.hprof"

echo "== hprof: generate fixture (seed material '$SEED') =="
META="$(php "$ROOT/scripts/dev/hprof/dump-fixture.php" "--seed=$SEED" "--out=$FIXTURE")"
echo "$META"

echo "== hprof: strings -a recovers every planted secret =="
STRINGS="$(strings -a "$FIXTURE")"
FAIL=0
while IFS= read -r secret; do
    [ -z "$secret" ] && continue
    if ! grep -qF -- "$secret" <<<"$STRINGS"; then
        echo "MISSING from strings -a: $secret" >&2
        FAIL=1
    fi
done < <(php -r '$m = json_decode(stream_get_contents(STDIN), true); foreach ($m["secrets"] as $s) echo $s, "\n";' <<<"$META")
if [ "$FAIL" -ne 0 ]; then
    exit 1
fi
if ! head -c 19 "$FIXTURE" | grep -q "JAVA PROFILE 1.0.2"; then
    echo "fixture does not start with the HPROF magic" >&2
    exit 1
fi
echo "ok."

if [ -z "$MAT" ]; then
    echo "== hprof: MAT not configured (--mat=DIR or MAT_HOME); skipping the independent-parser check =="
    exit 0
fi

PARSE="$MAT/ParseHeapDump.sh"
if [ ! -x "$PARSE" ]; then
    echo "MAT headless parser not found or not executable: $PARSE" >&2
    exit 2
fi
echo "== hprof: Eclipse MAT headless parse =="
# A parse failure exits non-zero; a silent no-op leaves no index behind — treat both as rejection.
"$PARSE" "$FIXTURE" org.eclipse.mat.api:overview
if ! ls "$OUT"/heapdump.*index >/dev/null 2>&1; then
    echo "MAT produced no index files: the fixture was not parsed" >&2
    exit 1
fi
echo "== hprof: PASS (MAT accepted the fixture) =="
