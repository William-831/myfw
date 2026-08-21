#!/bin/sh
set -e

# 自动生成 CA 证书（仅在首次启动/缺失时）
if [ ! -f /etc/myfw/ca/ca.pem ]; then
  echo "入口: 生成 CA ..."
  mkdir -p /etc/myfw/ca

  # 生成 CA 密钥
  openssl genrsa -out /etc/myfw/ca/ca.key 4096 2>/dev/null

  # 生成 CA 证书（CN=myfw-controller-ca）
  openssl req -x509 -new -nodes -key /etc/myfw/ca/ca.key -sha256 \
    -days 3650 -out /etc/myfw/ca/ca.pem -subj "/CN=myfw-controller-ca"

  # 生成 Controller 服务器证书（使用同一 CA 签发）
  openssl genrsa -out /etc/myfw/ca/server.key 2048 2>/dev/null
  openssl req -new -key /etc/myfw/ca/server.key \
    -subj "/CN=myfw-controller" -out /tmp/server.csr
  openssl x509 -req -in /tmp/server.csr -CA /etc/myfw/ca/ca.pem \
    -CAkey /etc/myfw/ca/ca.key -CAcreateserial \
    -days 3650 -out /etc/myfw/ca/server.crt

  chmod 600 /etc/myfw/ca/ca.key /etc/myfw/ca/server.key
  chmod 644 /etc/myfw/ca/ca.pem /etc/myfw/ca/server.crt
  rm -f /tmp/server.csr
  echo "入口: CA 生成完毕"
else
  echo "入口: CA 已存在，跳过生成"
fi

exec /usr/local/bin/myfw-controller "$@"