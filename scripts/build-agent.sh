#!/usr/bin/env bash
# build-agent.sh — 交叉编译 Agent 静态二进制(独立发布工具,与 Docker 部署解耦:
# 镜像构建已内置 amd64/arm64 两架构;本脚本仅供应急分发/自建下载站使用)。
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
