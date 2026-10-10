#!/bin/sh
# Lab only (operator machine, never CI): how far does a naive in-place unpack loop get through a served
# decoy archive on common Linux userlands? Re-run after every chain rebuild and paste the table into
# the ticket.
#
#   sh scripts/dev/decoy-chain/unpack-matrix.sh            # builds backup.zip via the PHP builder, runs images
#   IMAGES="alpine:3.20 debian:stable-slim" sh .../unpack-matrix.sh
#
# Each container runs the loop below with whatever unpackers the image has (no network, read-only input):
# extract the current archive next to itself, pick the largest newly extracted archive, repeat. It records
# the layer reached and the first error, which is the point — path walls, hostile names and unusual
# formats stop shell loops long before the bottom.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
IMAGES=${IMAGES:-"alpine:3.20 busybox:latest debian:stable-slim python:3.11-alpine debian:stable-slim+tools"}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

php -r 'require $argv[1]."/vendor/autoload.php"; $b=(new Funnypot\Core\Decoy\DecoyArchiveBuilder())->build("zip","backup",1); file_put_contents($argv[2], $b["body"]);' "$ROOT" "$WORK/backup.zip"

cat > "$WORK/loop.sh" <<'EOF'
#!/bin/sh
W=/tmp/w; mkdir -p $W; cp /in/backup.zip $W/; cur=$W/backup.zip; n=0; err=""
OS=$( (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || echo unknown)
x() { # archive dir
  case "$1" in
    *.zip) unzip -qq -o "$1" -d "$2" 2>&1 || bsdtar -xf "$1" -C "$2" 2>&1 ;;
    *.7z|*.iso) 7z x -y -bd -o"$2" "$1" >/dev/null 2>&1 || bsdtar -xf "$1" -C "$2" 2>&1 || echo "no 7z/iso tool" ;;
    *.tar.zst) zstd -dc "$1" | tar -xf - -C "$2" 2>&1 || echo "no zstd" ;;
    *.tar.lz4) lz4 -dc "$1" | tar -xf - -C "$2" 2>&1 || echo "no lz4" ;;
    *.cpio) (cd "$2" && cpio -id < "$1") 2>&1 || bsdtar -xf "$1" -C "$2" 2>&1 ;;
    *) tar -xf "$1" -C "$2" 2>&1 ;;
  esac
}
while [ $n -lt 3000 ]; do
  d=$(dirname "$cur")
  out=$(x "$cur" "$d") || true
  rm -f "$cur"   # a typical script deletes each part once unpacked, so the largest archive left is the next part
  nxt=$(find "$d" -type f 2>/dev/null | grep -E '\.(zip|7z|tar|gz|bz2|xz|zst|lz4|cpio|iso)$' | while IFS= read -r f; do printf '%s\t%s\n' "$(wc -c < "$f" 2>/dev/null || echo 0)" "$f"; done | sort -rn | head -1 | cut -f2-)
  if [ -z "$nxt" ] || [ ! -f "$nxt" ]; then err=$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-140); break; fi
  cur=$nxt; n=$((n+1))
done
echo "$OS | layers=$n | stopped: ${err:-no further archive found}"
EOF

for img in $IMAGES; do
  case $img in
    *+tools)  # a prepared attacker: every unpacker installed (needs network for apt)
      docker run --rm -v "$WORK:/in:ro" --tmpfs /tmp:size=1g "${img%+tools}" sh -c \
        'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq unzip 7zip libarchive-tools zstd lz4 cpio xz-utils bzip2 >/dev/null 2>&1; ln -sf /usr/bin/7zz /usr/local/bin/7z; sh /in/loop.sh' 2>&1 | tail -1 | sed 's/^/[+tools] /' ;;
    *)
      docker run --rm --network none -v "$WORK:/in:ro" --tmpfs /tmp:size=512m "$img" sh /in/loop.sh 2>&1 | tail -1 ;;
  esac
done
