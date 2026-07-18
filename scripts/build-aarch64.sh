#!/usr/bin/env bash
# Cross-build a static musl seq-agent inside Docker and extract the binary.
#
# Usage (docker needs sudo unless you're in the docker group):
#   sudo bash scripts/build-aarch64.sh                         # aarch64 (default)
#   sudo bash scripts/build-aarch64.sh <rust-target> <image-tag>
# e.g. armv7:
#   sudo bash scripts/build-aarch64.sh armv7-unknown-linux-musleabihf armv7-musleabihf
#
# Output: dist/seq-agent-<target>
set -euo pipefail

TARGET="${1:-aarch64-unknown-linux-musl}"
TAG="${2:-aarch64-musl}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/dist"
IMG="seq-agent-build:$TAG"

mkdir -p "$OUT"
cd "$REPO"

echo ">> docker build $TARGET (first run pulls a ~1.5 GB base image; be patient)..."
docker build -f Dockerfile.musl \
  --build-arg RUST_MUSL_CROSS_TAG="$TAG" \
  --build-arg TARGET="$TARGET" \
  -t "$IMG" .

cid="$(docker create "$IMG")"
trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid:/seq-agent" "$OUT/seq-agent-$TARGET"

# hand output back to the invoking user (so non-root tooling can read it)
if [ -n "${SUDO_UID:-}" ]; then
  chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$OUT"
fi

echo ">> extracted: $OUT/seq-agent-$TARGET"
ls -l "$OUT/seq-agent-$TARGET"
file "$OUT/seq-agent-$TARGET"
