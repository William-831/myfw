#!/usr/bin/env bash
# rebootstrap-agents.sh - 批量重新 bootstrap Agent
#
# 适用场景:Controller CA 丢失(重新 gen-ca)或数据库彻底重建且无备份时,
# 存量 Agent 旧证书签名失效,必须逐台重新 bootstrap 接入。本脚本自动化该流程。
#
# 注意:若只是 Controller 数据库重建而 CA(dev-ca)仍在,无需本脚本——
# Controller 已内置 auto_reregister,存量 Agent 会自动重注册恢复 ACTIVE。
#
# 流程(每台 Agent):
#   1. 在 Controller 拿一次性 bootstrap token
#   2. ssh 到 Agent:备份 agent.yaml + 旧证书,写入 token,重启 Agent
#   3. 节点以 PENDING 出现,需到 Web 审批中心 approve
#
# 用法:
#   AGENTS="root@host1 root@host2" ./scripts/rebootstrap-agents.sh
#   AGENTS="root@host1" CONTROLLER=http://10.0.0.1:8080 ./scripts/rebootstrap-agents.sh
#
# 环境变量:
#   AGENTS      必填,空格分隔的 Agent SSH 目标(user@host)
#   CONTROLLER  Controller Web 地址,默认 http://127.0.0.1:8080
#   AGENT_YAML  Agent 配置路径(远程),默认 /home/myFW/agent.yaml
#   AGENT_CERT  Agent 证书路径(远程),默认 /home/myFW/agent.crt
#   AGENT_SVC   Agent systemd 服务名,默认 myfw-agent
set -euo pipefail

AGENTS="${AGENTS:?请设置 AGENTS=\"user@host1 user@host2\"}"
CONTROLLER="${CONTROLLER:-http://127.0.0.1:8080}"
AGENT_YAML="${AGENT_YAML:-/home/myFW/agent.yaml}"
AGENT_CERT="${AGENT_CERT:-/home/myFW/agent.crt}"
AGENT_SVC="${AGENT_SVC:-myfw-agent}"

for REMOTE in $AGENTS; do
  echo "=== [$REMOTE] 重新 bootstrap ==="

  # 1. 在 Controller 拿一次性 bootstrap token
  TOKEN=$(curl -fsS -X POST "$CONTROLLER/api/v1/nodes/bootstrap" \
    -H "Content-Type: application/json" -d '{"note":"rebootstrap"}' \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
  if [[ -z "$TOKEN" ]]; then
    echo "[$REMOTE] 获取 token 失败,跳过"
    continue
  fi

  # 2. 远程:备份配置+证书,写入 token,重启 Agent
  #    heredoc 中 $TOKEN/$AGENT_* 在本地展开后传给远程 bash
  ssh "$REMOTE" bash <<EOF
set -e
cp "$AGENT_YAML" "$AGENT_YAML.bak" 2>/dev/null || true
# 删除旧 bootstrap_token(若有),在 endpoint 行后插入新 token
sed -i '/^[[:space:]]*bootstrap_token:/d' "$AGENT_YAML"
sed -i "/endpoint:/a\\  bootstrap_token: \"$TOKEN\"" "$AGENT_YAML"
[[ -f "$AGENT_CERT" ]] && mv "$AGENT_CERT" "$AGENT_CERT.bak"
systemctl restart "$AGENT_SVC"
sleep 3
echo "--- 启动日志 ---"
journalctl -u "$AGENT_SVC" --no-pager -n 6
EOF

  echo "[$REMOTE] 完成(节点将以 PENDING 出现,请到 Web approve)"
  echo
done

echo "全部完成。请到 $CONTROLLER 的审批中心 approve 各节点。"
