#!/bin/sh
set -e

# 自动生成 CA 证书（仅在首次启动/缺失时）。
# CA 一旦生成即持久化（docker-compose.prod.yml 挂载 deploy/docker/dev-ca:/etc/myfw/ca），
# 容器重建不会换 CA，已注册 Agent 的客户端证书不失效。
if [ ! -f /etc/myfw/ca/ca.pem ] || [ ! -f /etc/myfw/ca/ca.key ]; then
  echo "入口: 生成 CA ..."
  mkdir -p /etc/myfw/ca

  # 生成 CA 密钥
  openssl genrsa -out /etc/myfw/ca/ca.key 4096 2>/dev/null

  # 生成 CA 证书（CN=myfw-controller-ca）
  openssl req -x509 -new -nodes -key /etc/myfw/ca/ca.key -sha256 \
    -days 3650 -out /etc/myfw/ca/ca.pem -subj "/CN=myfw-controller-ca"
else
  echo "入口: CA 已存在，跳过生成"
fi

# 生成 Controller 服务器证书（缺失时用同一 CA 签发）。
# Agent 连接时校验服务器证书的 ServerName，因此 SAN 必须覆盖 Agent 使用的
# Controller 地址：MYFW_SAN="IP:10.0.0.5,DNS:myfw.example.com"（逗号分隔）。
if [ ! -f /etc/myfw/ca/server.crt ] || [ ! -f /etc/myfw/ca/server.key ]; then
  echo "入口: 生成 server 证书 ..."
  openssl genrsa -out /etc/myfw/ca/server.key 2048 2>/dev/null
  if [ -n "${MYFW_SAN:-}" ]; then
    # 带 SAN(Agent 校验 ServerName;需带类型前缀 IP:/DNS:)
    openssl req -new -key /etc/myfw/ca/server.key \
      -subj "/CN=myfw-controller" -addext "subjectAltName=${MYFW_SAN}" \
      -out /tmp/server.csr
    openssl x509 -req -in /tmp/server.csr -CA /etc/myfw/ca/ca.pem \
      -CAkey /etc/myfw/ca/ca.key -CAcreateserial \
      -copy_extensions copy -days 3650 -out /etc/myfw/ca/server.crt
  else
    openssl req -new -key /etc/myfw/ca/server.key \
      -subj "/CN=myfw-controller" -out /tmp/server.csr
    openssl x509 -req -in /tmp/server.csr -CA /etc/myfw/ca/ca.pem \
      -CAkey /etc/myfw/ca/ca.key -CAcreateserial \
      -days 3650 -out /etc/myfw/ca/server.crt
  fi
  rm -f /tmp/server.csr
  echo "入口: server 证书生成完毕"
else
  echo "入口: server 证书已存在，跳过生成"
fi

chmod 600 /etc/myfw/ca/ca.key /etc/myfw/ca/server.key
chmod 644 /etc/myfw/ca/ca.pem /etc/myfw/ca/server.crt

exec /usr/local/bin/myfw-controller "$@"
