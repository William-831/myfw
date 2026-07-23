#!/usr/bin/env bash
# gen-ca.sh — generate a DEV-ONLY self-signed CA and controller server cert.
# NEVER use the output of this script in production. See docs/deployment.md § 4.2
# for the production CA procedure.
set -euo pipefail

CA_DIR="${MYFW_CA_DIR:-./dev-ca}"
CN_SERVER="${MYFW_SERVER_CN:-controller}"
SAN_DNS="${MYFW_SERVER_DNS:-localhost}"
SAN_IP="${MYFW_SERVER_IP:-127.0.0.1}"

mkdir -p "$CA_DIR"
cd "$CA_DIR"

if [[ -f ca.pem ]]; then
  echo "gen-ca: $CA_DIR/ca.pem already exists, skipping (rm -rf $CA_DIR to regenerate)"
  exit 0
fi

echo "gen-ca: generating dev CA in $CA_DIR ..."

# CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -subj "/CN=myfw-dev-ca" -out ca.pem

# Server cert
openssl genrsa -out server.key 4096
openssl req -new -key server.key -subj "/CN=${CN_SERVER}" -out server.csr

cat > server.ext <<EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = ${SAN_DNS}
IP.1  = ${SAN_IP}
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days 730 -sha256 -extfile server.ext

chmod 0600 ca.key server.key
rm -f server.csr server.ext

echo "gen-ca: done. Files in $CA_DIR (dev only, git-ignored)."
