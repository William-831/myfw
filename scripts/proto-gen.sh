#!/usr/bin/env bash
# proto-gen.sh — regenerate Go code from proto/myfw/v1/*.proto into api/.
# Requires: protoc, protoc-gen-go, protoc-gen-go-grpc (on PATH; typically
# $(go env GOPATH)/bin). See docs/development-plan.md § M1.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Make sure the go-installed plugins are reachable.
export PATH="$(go env GOPATH)/bin:$PATH"

for bin in protoc protoc-gen-go protoc-gen-go-grpc; do
  command -v "$bin" >/dev/null 2>&1 || { echo "proto-gen: '$bin' not found on PATH" >&2; exit 1; }
done

# Generated Go lands under ./api (module path iptables-tool/api/...).
protoc \
  --proto_path=proto \
  --go_out=. \
  --go_opt=module=iptables-tool \
  --go-grpc_out=. \
  --go-grpc_opt=module=iptables-tool \
  proto/myfw/v1/*.proto

echo "proto-gen: done -> api/myfw/v1/"
