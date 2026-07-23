#!/usr/bin/env bash
# build-agent.sh — cross-compile the agent as static binaries for Linux.
# See docs/deployment.md § 5.1.
set -euo pipefail

DIST="${DIST:-dist}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"

mkdir -p "$DIST"

for arch in amd64 arm64; do
  echo "build-agent: linux/${arch} ..."
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" \
    go build -trimpath -ldflags="$LDFLAGS" \
    -o "$DIST/myfw-agent-linux-${arch}" ./cmd/agent
done

echo "build-agent: done -> $DIST/"
file "$DIST"/myfw-agent-linux-* 2>/dev/null || true
