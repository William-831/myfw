#!/bin/bash
# 清理 249 上的旧 Agent（旧二进制无自毁逻辑，手动清理以便用新二进制测试）
systemctl stop myfw-agent 2>/dev/null || true
systemctl disable myfw-agent 2>/dev/null || true
rm -rf /etc/myfw-agent /var/lib/myfw-agent
rm -f /usr/local/bin/myfw-agent /etc/systemd/system/myfw-agent.service
systemctl daemon-reload
echo "clean-agent-done"
