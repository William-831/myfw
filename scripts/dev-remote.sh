#!/usr/bin/env bash
# dev-remote.sh - 远程 Linux 日常迭代联调一键脚本(进程态:SQLite + mTLS dev-ca)。
#
# 配套 docs/deployment.md §3 的"远程编译/运行"约定:本机仅编辑+push,远程执行本脚本。
# 用法:
#   ./scripts/dev-remote.sh ca         首次生成 dev-ca(同机联调零配置可用)
#   ./scripts/dev-remote.sh web        前端 Vite dev server(:5173,HMR,代理 /api 到 :8080)
#   ./scripts/dev-remote.sh controller 前台启动 Controller(默认 SQLite)
#   ./scripts/dev-remote.sh ob         Controller 切外部 OceanBase(需 MYFW_DB_DSN)
#   ./scripts/dev-remote.sh agent      编译并以 root 前台启动 Agent(同机接入)
#
# 分机联调:导出 MYFW_CONTROLLER_ENDPOINT=<对外IP>:9090,
#           并在 ca 步骤前导出 MYFW_SERVER_IP=<对外IP> MYFW_SERVER_DNS=<域名>。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Agent 接入地址;同机用 127.0.0.1(gen-ca 默认 SAN 已覆盖)
CONTROLLER_ENDPOINT="${MYFW_CONTROLLER_ENDPOINT:-127.0.0.1:9090}"

# 首次生成开发 CA(已存在则跳过)
cmd_ca() {
  if [[ -f dev-ca/ca.pem ]]; then
    echo "[dev] dev-ca 已存在,跳过(rm -rf dev-ca 可重生成)"
    return
  fi
  echo "[dev] 生成 dev-ca(SAN 默认 localhost/127.0.0.1)"
  make gen-ca
}

# 前台启动 Controller:默认 SQLite,env 可覆盖驱动/DSN
cmd_controller() {
  [[ -f dev-ca/ca.pem ]] || cmd_ca
  export MYFW_DB_DRIVER="${MYFW_DB_DRIVER:-sqlite}"
  export MYFW_DB_DSN="${MYFW_DB_DSN:-./dev.db}"
  echo "[dev] Controller 启动: driver=$MYFW_DB_DRIVER dsn=$MYFW_DB_DSN (Ctrl-C 停止)"
  go run ./cmd/controller --config configs/controller.dev.yaml
}

# Controller 切到外部 OceanBase(MySQL 协议)
cmd_ob() {
  : "${MYFW_DB_DSN:?需要 MYFW_DB_DSN(OB 连接串),例如 myfw:pass@tcp(ob:2881)/myfw?...}"
  export MYFW_DB_DRIVER=mysql
  cmd_controller
}

# 前端 Vite dev server:HMR 热更新,代理 /api、/rpc 到后端 :8080(需先起 controller)
cmd_web() {
  [[ -d web/node_modules ]] || { echo "[dev] 安装前端依赖(首次)..."; (cd web && npm install); }
  echo "[dev] Vite dev server :5173(HMR),浏览器访问 http://<本机IP>:5173"
  (cd web && npm run dev -- --host 0.0.0.0)
}

# 编译并以 root 前台启动 Agent;首次自动生成 dev-agent.yaml 模板
cmd_agent() {
  [[ -f dev-ca/ca.pem ]] || { echo "[dev] 请先跑: $0 ca"; exit 1; }
  echo "[dev] 编译 Agent ..."; go build -o dist/myfw-agent ./cmd/agent

  if [[ ! -f dev-agent.yaml ]]; then
    cat >dev-agent.yaml <<EOF
controller:
  endpoint: ${CONTROLLER_ENDPOINT}
  tls:
    ca_file: ./dev-ca/ca.pem
    cert_file: ./dev-agent.crt
    key_file: ./dev-agent.key
  bootstrap_token: "REPLACE_ME"   # 从 Web「新增待接入节点」拿 token 后替换
node:
  labels: [dev]
EOF
    chmod 0600 dev-agent.yaml
    echo "[dev] 已生成 dev-agent.yaml,请填入 bootstrap_token 后重跑: $0 agent"
    exit 0
  fi

  if grep -q REPLACE_ME dev-agent.yaml; then
    echo "[dev] dev-agent.yaml 仍是占位 token,请先在 Web 新增节点并填入,再重跑: $0 agent"
    exit 1
  fi

  echo "[dev] Agent 前台启动(需 root 操作 Netfilter,Ctrl-C 停止)"
  sudo ./dist/myfw-agent --config dev-agent.yaml
}

case "${1:-}" in
  ca)         cmd_ca ;;
  web)        cmd_web ;;
  controller) cmd_controller ;;
  ob)         cmd_ob ;;
  agent)      cmd_agent ;;
  *) echo "用法: $0 {ca|controller|web|agent|ob}"; exit 1 ;;
esac
