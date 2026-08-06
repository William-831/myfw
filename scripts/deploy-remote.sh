#!/usr/bin/env bash
# deploy-remote.sh - 远程测试机一键部署（Docker 形式启动 Controller）。
#
# 在目标 Linux 机器上执行，前置条件：
#   /home/myfw 下已放入 myfw-src.tar.gz（源码包）与 myfw-agent-linux-amd64（交叉编译产物）。
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

echo "=== [1/7] 解压源码 ==="
tar -xzf myfw-src.tar.gz -C "$WORKDIR"

echo "=== [2/7] 生成 CA（SAN=$SAN）==="
SAN="$SAN" ./scripts/gen-ca.sh

echo "=== [3/7] 部署 Agent 二进制 ==="
mkdir -p agent
mv myfw-agent-linux-amd64 agent/myfw-agent-linux-amd64
chmod +x agent/myfw-agent-linux-amd64

echo "=== [4/7] 准备数据目录与 .env ==="
mkdir -p data
HMAC="$(openssl rand -hex 32)"
cat > .env <<EOF
MYFW_DB_DRIVER=sqlite
MYFW_DB_DSN=/data/myfw.db
MYFW_HMAC_SECRET=$HMAC
EOF
chmod 600 .env
echo "    HMAC 已生成，DB=sqlite(/data/myfw.db)"

echo "=== [5/7] 构建镜像（多阶段：前端 + Controller）==="
$DC -f docker-compose.prod.yml build

echo "=== [6/7] 启动 ==="
$DC -f docker-compose.prod.yml up -d

echo "=== [7/7] 验证 ==="
sleep 5
$DC -f docker-compose.prod.yml ps
echo "--- healthz ---"
curl -fsS http://localhost:8080/healthz && echo
echo "--- 下载路由 ---"
curl -fsS -o /dev/null -w "ca.pem:           %{http_code}\n" http://localhost:8080/download/ca.pem
curl -fsS -o /dev/null -w "agent linux-amd64:%{http_code}\n" http://localhost:8080/download/agent/linux-amd64
echo "=== 部署完成，Web 控制台：http://$SAN:8080 ==="
