#!/usr/bin/env bash
# upload-frontend.sh - 本地构建前端并上传到远程服务器(本地 Windows git bash 运行)。
#
# 远程无需 Node:本地 npm run build 后把 web/dist 上传到远程,
# Controller 容器挂载的 dist 即时更新,浏览器 Ctrl+F5 刷新生效。
#
# 用法:
#   REMOTE=user@10.0.0.10 ./scripts/upload-frontend.sh
#   REMOTE=user@host DEST=/home/user/go-iptablesops ./scripts/upload-frontend.sh
#   SKIP_BUILD=1 REMOTE=user@host ./scripts/upload-frontend.sh   # 跳过构建,仅上传
#
# 环境变量:
#   REMOTE      必填,SSH 目标(user@host)
#   DEST        远程项目目录,默认 ~/go-iptablesops
#   SKIP_BUILD  =1 时跳过本地构建,直接上传已有 web/dist
set -euo pipefail

REMOTE="${REMOTE:?请设置 REMOTE=user@host}"
DEST="${DEST:-~/go-iptablesops}"
HOST="${REMOTE#*@}"                       # 从 user@host 提取 host,用于提示访问地址
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# 1. 本地构建(SKIP_BUILD=1 可跳过)
if [[ "${SKIP_BUILD:-0}" == "1" ]]; then
  echo "[upload] 跳过构建(SKIP_BUILD=1)"
else
  [[ -d web/node_modules ]] || { echo "[upload] 缺少 web/node_modules,请先: cd web && npm install"; exit 1; }
  echo "[upload] 本地构建前端(vite build)..."
  ( cd web && npm run build )
fi

# 2. 校验本地产物
[[ -f web/dist/index.html ]] || { echo "[upload] 构建产物缺失:web/dist/index.html"; exit 1; }

# 3. 清理远程旧 dist 并上传新产物
echo "[upload] 上传 -> ${REMOTE}:${DEST}/web/dist"
ssh "$REMOTE" "rm -rf ${DEST}/web/dist && mkdir -p ${DEST}/web"
scp -C -r web/dist "${REMOTE}:${DEST}/web/"

# 4. 远程校验
if ssh "$REMOTE" "test -f ${DEST}/web/dist/index.html"; then
  echo "[upload] 远程产物校验通过"
else
  echo "[upload] 远程校验失败:${DEST}/web/dist/index.html 未找到" >&2
  exit 1
fi

echo "[upload] 完成。浏览器访问 http://${HOST}:8080 并 Ctrl+F5 强刷。"
