#!/usr/bin/env bash
# gen-ca.sh - 生成生产级 CA 与 Controller server 证书（mTLS）。
#
# Controller 的 gRPC 启用 mTLS：Agent 首次用 bootstrap token 换取由本 CA 签发的
# 客户端证书，之后凭该证书长连接。server 证书的 SAN 必须覆盖 Agent 连接
# Controller 时使用的地址——即管理员访问 Web 控制台用的域名/IP（前端"添加节点"
# 脚本以 window.location.hostname 生成 endpoint，二者必须一致）。
#
# 用法：
#   SAN="myfw.example.com"             ./scripts/gen-ca.sh        # 域名
#   SAN="myfw.example.com,10.0.0.5"    ./scripts/gen-ca.sh        # 域名 + 内网 IP
#   SAN="10.0.0.5"                     ./scripts/gen-ca.sh        # 纯 IP
#
# 环境变量：
#   CA_DIR  证书输出目录，默认 dev-ca（与 docker-compose.prod.yml 挂载一致）
#   SAN     必填，server 证书覆盖的域名/IP，逗号分隔
#   DAYS    证书有效期（天），默认 3650（10 年）
set -euo pipefail

CA_DIR="${CA_DIR:-dev-ca}"
DAYS="${DAYS:-3650}"
SAN="${SAN:?请设置 SAN=\"域名或IP\"，例如 SAN=myfw.example.com,10.0.0.5}"

command -v openssl >/dev/null || { echo "gen-ca: 需要 openssl" >&2; exit 1; }

mkdir -p "$CA_DIR"

# 1. CA：已存在则跳过，避免覆盖导致所有已签发的 Agent 客户端证书失效。
if [[ ! -f "$CA_DIR/ca.key" || ! -f "$CA_DIR/ca.pem" ]]; then
  echo "gen-ca: 生成 CA..."
  openssl genrsa -out "$CA_DIR/ca.key" 4096 2>/dev/null
  openssl req -x509 -new -nodes -key "$CA_DIR/ca.key" \
    -subj "/CN=myfw-controller-ca" -days "$DAYS" \
    -out "$CA_DIR/ca.pem"
else
  echo "gen-ca: CA 已存在，跳过（不覆盖）"
fi

# 2. server 证书：SAN 覆盖 Agent 连接地址。
echo "gen-ca: 生成 server 证书，SAN=$SAN ..."
openssl genrsa -out "$CA_DIR/server.key" 2048 2>/dev/null

san_conf="$(mktemp)"
trap 'rm -f "$san_conf" "$CA_DIR/server.csr"' EXIT
{
  echo "[req]"
  echo "distinguished_name = dn"
  echo "req_extensions = v3_req"
  echo "prompt = no"
  echo "[dn]"
  echo "CN = myfw-controller"
  echo "[v3_req]"
  echo "keyUsage = digitalSignature, keyEncipherment"
  echo "extendedKeyUsage = serverAuth"
  echo "subjectAltName = @alt_names"
  echo "[alt_names]"
  idx=1
  IFS=',' read -ra entries <<< "$SAN"
  for e in "${entries[@]}"; do
    e="$(echo "$e" | xargs)"          # 去首尾空白
    [[ -z "$e" ]] && continue
    if [[ "$e" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      echo "IP.$idx = $e"             # IP 地址走 IP SAN
    else
      echo "DNS.$idx = $e"            # 域名走 DNS SAN
    fi
    idx=$((idx + 1))
  done
} > "$san_conf"

openssl req -new -key "$CA_DIR/server.key" -config "$san_conf" -out "$CA_DIR/server.csr"
openssl x509 -req -in "$CA_DIR/server.csr" \
  -CA "$CA_DIR/ca.pem" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
  -days "$DAYS" -out "$CA_DIR/server.crt" \
  -extensions v3_req -extfile "$san_conf" 2>/dev/null

chmod 600 "$CA_DIR/ca.key" "$CA_DIR/server.key"
chmod 644 "$CA_DIR/ca.pem" "$CA_DIR/server.crt"

echo "gen-ca: 完成 -> $CA_DIR/"
echo "  ca.pem / ca.key          Controller CA（挂载到容器 /etc/myfw/ca/）"
echo "  server.crt / server.key  Controller server 证书"
echo ""
echo "⚠ Agent 连接地址必须在 SAN 内：$SAN"
echo "  管理员访问 Web 控制台用的域名/IP 即 Agent 的 endpoint，需与此一致。"
