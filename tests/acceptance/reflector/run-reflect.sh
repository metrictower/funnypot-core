#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 0 ]; then
    echo 'run-reflect.sh accepts no arguments; its image, target, template and limits are fixed' >&2
    exit 2
fi

readonly here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly root=$(cd "$here/../../.." && pwd)
readonly output="$root/.reflector-acceptance-output"
readonly suffix=$$
readonly image="funnypot-reflector-acceptance:$suffix"
readonly container="funnypot-reflector-acceptance-$suffix"

cd "$root"
if [ -n "$(git status --porcelain)" ]; then
    echo 'refusing to attest a dirty source tree' >&2
    exit 2
fi
if [ -e "$output" ]; then
    echo "refusing to overwrite existing evidence: $output" >&2
    exit 2
fi
mkdir -m 0700 "$output"

image_built=0
container_created=0
cleanup() {
    if [ "$container_created" -eq 1 ]; then
        if docker container inspect "$container" >/dev/null 2>&1; then
            docker container rm --force "$container" >/dev/null
        fi
    fi
    if [ "$image_built" -eq 1 ]; then
        if docker image inspect "$image" >/dev/null 2>&1; then
            docker image rm "$image" >/dev/null
        fi
    fi
}
on_signal() {
    cleanup
    exit 143
}
trap cleanup EXIT
trap on_signal INT TERM

# This is the only online phase. Dockerfile verifies exact archive sizes/hashes before extraction.
docker build --platform linux/amd64 --file "$here/Dockerfile" --tag "$image" "$root"
image_built=1

container_created=1
set +e
docker run \
    --name "$container" \
    --platform linux/amd64 \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
    --mount "type=bind,src=$output,dst=/output" \
    --user "$(id -u):$(id -g)" \
    --cap-drop ALL \
    --security-opt no-new-privileges \
    --cpus 2 \
    --memory 2g \
    --pids-limit 128 \
    --stop-timeout 5 \
    "$image"
status=$?
set -e

if [ "$status" -ne 0 ]; then
    echo "reflector acceptance failed (exit $status); evidence retained at $output" >&2
    exit "$status"
fi
if [ ! -s "$output/receipt.json" ] || [ -e "$output/verification-error.txt" ]; then
    echo "reflector acceptance did not produce a verified receipt; evidence retained at $output" >&2
    exit 1
fi

echo "reflector acceptance passed; receipt: $output/receipt.json"
