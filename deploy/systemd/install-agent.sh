#!/usr/bin/env bash
# install-agent.sh — 被管节点一键安装 MYFW Agent(systemd 服务)。
#
# 由 Controller 镜像内置并通过 /download/agent/install-agent.sh 提供。
# 被管节点(需 root)执行:
#   export MYFW_BOOTSTRAP_TOKEN=<节点令牌>
#   curl -fsSL http://<控制器IP>:8080/download/agent/install-agent.sh | bash
# 脚本自动识别节点 CPU 架构,下载对应 Agent 二进制(amd64/arm64)。
set -euo pipefail

CONTROLLER="${MYFW_CONTROLLER:-controller.example.com:9090}"
BOOTSTRAP_TOKEN="${MYFW_BOOTSTRAP_TOKEN:-REPLACE_ME}"
WEB_BASE="${MYFW_WEB_URL:-https://controller.example.com:8080}"

# 1. 识别节点架构
case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64) ARCH=arm64 ;;
  *) echo "install-agent: 不支持的架构 $(uname -m)" >&2; exit 1 ;;
esac

if [[ $EUID -ne 0 ]]; then
  echo "install-agent: must run as root" >&2
  exit 1
fi

# 2. 下载 Agent 二进制与 CA
curl -fsSL -o /usr/local/bin/myfw-agent "$WEB_BASE/download/agent/linux-$ARCH"
chmod 0755 /usr/local/bin/myfw-agent
install -d -m 0755 /etc/myfw-agent
install -d -m 0700 /var/lib/myfw-agent
curl -fsSL -o /etc/myfw-agent/ca.pem "$WEB_BASE/download/ca.pem"

# 3. 生成配置(bootstrap token 由环境变量注入,不预渲染)
cat >/etc/myfw-agent/agent.yaml <<EOF
controller:
  endpoint: ${CONTROLLER}
  tls:
    ca_file: /etc/myfw-agent/ca.pem
    cert_file: /etc/myfw-agent/agent.crt
    key_file: /etc/myfw-agent/agent.key
  bootstrap_token: "${BOOTSTRAP_TOKEN}"
node:
  labels: []
EOF
chmod 0600 /etc/myfw-agent/agent.yaml

# 4. systemd 单元(内联,内容与 deploy/systemd/myfw-agent.service 一致)
cat >/etc/systemd/system/myfw-agent.service <<'SERVICE'
[Unit]
Description=MYFW Agent(防火墙执行面)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myfw-agent --config /etc/myfw-agent/agent.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SERVICE

# 5. 启动
systemctl daemon-reload
systemctl enable --now myfw-agent

echo "install-agent: done($ARCH). 日志: journalctl -u myfw-agent -f"