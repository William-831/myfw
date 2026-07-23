#!/usr/bin/env bash
# install-agent.sh — install the MYFW agent as a bare-metal systemd service.
#
# In production this script is rendered/served by the Controller with the
# bootstrap token and endpoint filled in (see docs/deployment.md § 5.3).
# This committed copy is the template with placeholders.
set -euo pipefail

CONTROLLER="${MYFW_CONTROLLER:-controller.example.com:9090}"
BOOTSTRAP_TOKEN="${MYFW_BOOTSTRAP_TOKEN:-REPLACE_ME}"
DOWNLOAD_URL="${MYFW_AGENT_URL:-https://controller.example.com:8080/download/agent/linux-amd64}"
CA_URL="${MYFW_CA_URL:-https://controller.example.com:8080/pki/ca.pem}"

if [[ $EUID -ne 0 ]]; then
  echo "install-agent: must run as root" >&2
  exit 1
fi

# 1. binary
curl -fsSL -o /usr/local/bin/myfw-agent "$DOWNLOAD_URL"
chmod 0755 /usr/local/bin/myfw-agent

# 2. dirs + CA
install -d -m 0755 /etc/myfw-agent
install -d -m 0700 /var/lib/myfw-agent
curl -fsSL -o /etc/myfw-agent/ca.pem "$CA_URL"

# 3. config
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

# 4. systemd unit
install -m 0644 "$(dirname "$0")/myfw-agent.service" /etc/systemd/system/myfw-agent.service

# 5. start
systemctl daemon-reload
systemctl enable --now myfw-agent

echo "install-agent: done. Follow logs with: journalctl -u myfw-agent -f"
