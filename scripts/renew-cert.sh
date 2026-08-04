#!/usr/bin/env bash
# renew-cert.sh - 批量触发节点证书续签
#
# 适用场景:证书临期或自动续签失败时,管理员主动触发节点续签。
# 续签由 Agent 用旧证书发起 CSR,Controller 签发新证书后 Agent 重建连接加载新证书。
# 详见 docs/design.md § 13。
#
# 用法:
#   NODE_IDS="n_xxx n_yyy" ./scripts/renew-cert.sh
#   NODE_IDS="n_xxx" CONTROLLER=http://10.0.0.1:8080 ./scripts/renew-cert.sh
#
# 环境变量:
#   NODE_IDS    必填,空格分隔的节点 ID
#   CONTROLLER  Controller Web 地址,默认 http://127.0.0.1:8080
#   USER        登录用户名,默认 root
#   PASSWORD    登录密码,默认 admin123(首次部署后请修改)
set -euo pipefail

NODE_IDS="${NODE_IDS:?请设置 NODE_IDS=\"node_id1 node_id2\"}"
CONTROLLER="${CONTROLLER:-http://127.0.0.1:8080}"
USER="${USER:-root}"
PASSWORD="${PASSWORD:-admin123}"

# 登录获取 token
TOKEN=$(curl -fsS -X POST "$CONTROLLER/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USER\",\"password\":\"$PASSWORD\"}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
if [[ -z "$TOKEN" ]]; then
  echo "登录失败,请检查 USER/PASSWORD"
  exit 1
fi

for ID in $NODE_IDS; do
  echo "=== [$ID] 触发续签 ==="
  resp=$(curl -sS -X POST "$CONTROLLER/api/v1/nodes/$ID/renew-cert" \
    -H "Authorization: Bearer $TOKEN" || echo "REQUEST_FAILED")
  if [[ "$resp" == "REQUEST_FAILED" ]]; then
    echo "[$ID] 续签指令下发失败"
  else
    echo "[$ID] $resp"
  fi
done

echo "全部完成。续签后节点将短暂重连,刷新节点列表查看新证书过期时间。"
