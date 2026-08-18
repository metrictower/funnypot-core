#!/usr/bin/env bash
#
# Real-nuclei acceptance proof (SPEC §6). Stands up the package behind `php -S`
# and runs REAL nuclei (Docker) against it, then diffs the fired template ids
# against golden.txt. Exits non-zero if any golden id fails to fire.
#
# Networking: nuclei runs in Docker and reaches the host via host.docker.internal (mapped
# with --add-host=…:host-gateway). On a Linux CI runner that gateway is the docker bridge IP,
# so the server MUST bind 0.0.0.0 — a 127.0.0.1 bind is unreachable from the container there
# (it works on macOS Docker Desktop by luck). `--network=host` is not an option: it does not
# reach the host on macOS Docker Desktop.
#
# Usage: tests/acceptance/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PORT="${PORT:-8899}"
IMAGE="${NUCLEI_IMAGE:-projectdiscovery/nuclei:latest}"
OUT="$HERE/nuclei-output.jsonl"

cd "$ROOT"

echo "== starting php -S 0.0.0.0:$PORT (full compiled index) =="
php -S "0.0.0.0:$PORT" tests/acceptance/server.php >"$HERE/server.log" 2>&1 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for the server to answer.
for _ in $(seq 1 50); do
  if curl -sf "http://127.0.0.1:$PORT/.git/config" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo "== pulling nuclei image if missing =="
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"

echo "== running real nuclei against host.docker.internal:$PORT =="
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$HERE/golden-templates:/gt:ro" \
  "$IMAGE" \
  -u "http://host.docker.internal:$PORT" \
  -t /gt \
  -jsonl -no-interactsh -disable-update-check -silent \
  >"$OUT" 2>"$HERE/nuclei.stderr" || true

echo "== nuclei jsonl =="
cat "$OUT" || true
echo

# Fired ids (jq if present, else grep the template-id field).
if command -v jq >/dev/null 2>&1; then
  jq -r 'select(."template-id"!=null) | ."template-id"' "$OUT" | sort -u >"$HERE/fired.txt"
else
  grep -o '"template-id":"[^"]*"' "$OUT" | sed 's/.*:"//;s/"$//' | sort -u >"$HERE/fired.txt"
fi

sort -u "$HERE/golden.txt" >"$HERE/golden.sorted"

echo "== FIRED =="; cat "$HERE/fired.txt"
echo "== MISSING (golden not fired) =="
MISSING="$(comm -23 "$HERE/golden.sorted" "$HERE/fired.txt" || true)"
echo "${MISSING:-<none>}"
echo "== UNEXPECTED (fired but not golden) =="
comm -13 "$HERE/golden.sorted" "$HERE/fired.txt" || true

rm -f "$HERE/golden.sorted"

if [ -n "${MISSING:-}" ]; then
  echo "RESULT: FAIL — golden templates did not fire."
  exit 1
fi
echo "RESULT: PASS — every golden template fired."
