#!/usr/bin/env bash
# deploy-remote.sh - 远程测试机一键部署（Docker 形式启动 Controller）。
#
# 在目标 Linux 机器上执行，前置条件：
#   /home/myfw 下已放入 myfw-src.tar.gz（源码包）。
#   Agent 二进制随镜像内置,无需单独准备/上传。
#
# 用法（默认测试机 192.168.80.249）：
#   WORKDIR=/home/myfw SAN=192.168.80.249 ./scripts/deploy-remote.sh
set -euo pipefail

WORKDIR="${WORKDIR:-/home/myfw}"
SAN="${SAN:-192.168.80.249}"

cd "$WORKDIR"

# 检测 compose 命令：v2 插件优先，回退 v1 独立二进制
if docker compose version >/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC="docker-compose"
else
  echo "ERROR: 未找到 docker compose（v2 插件或 v1 二进制），请先安装" >&2
  exit 1
fi
echo "compose 命令: $DC"

echo "=== [1/6] 解压源码 ==="
tar -xzf myfw-src.tar.gz -C "$WORKDIR"

echo "=== [2/6] 生成 CA（SAN=$SAN）==="
CA_DIR=deploy/docker/dev-ca SAN="$SAN" ./scripts/gen-ca.sh

echo "=== [3/6] 准备数据目录与 .env ==="
mkdir -p deploy/docker/data
HMAC="$(openssl rand -hex 32)"
cat > .env <<EOF
MYFW_DB_DRIVER=sqlite
MYFW_DB_DSN=/data/myfw.db
MYFW_HMAC_SECRET=$HMAC
EOF
chmod 600 .env
echo "    HMAC 已生成，DB=sqlite(/data/myfw.db)"

echo "=== [4/6] 构建镜像（多阶段：前端 + Controller + Agent）==="
$DC -f docker-compose.prod.yml build

echo "=== [5/6] 启动 ==="
$DC -f docker-compose.prod.yml up -d

echo "=== [6/6] 验证 ==="
sleep 5
$DC -f docker-compose.prod.yml ps
echo "--- healthz ---"
curl -fsS http://localhost:8080/healthz && echo
echo "--- 下载路由 ---"
curl -fsS -o /dev/null -w "ca.pem:           %{http_code}\n" http://localhost:8080/download/ca.pem
curl -fsS -o /dev/null -w "agent linux-amd64:%{http_code}\n" http://localhost:8080/download/agent/linux-amd64
curl -fsS -o /dev/null -w "agent linux-arm64:%{http_code}\n" http://localhost:8080/download/agent/linux-arm64
curl -fsS -o /dev/null -w "install-agent.sh: %{http_code}\n" http://localhost:8080/download/agent/install-agent.sh
echo "=== 部署完成，Web 控制台：http://$SAN:8080 ==="
