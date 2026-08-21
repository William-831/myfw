# Controller CA 证书目录(自动管理,请勿删除)

本目录由 docker-compose.prod.yml 挂载到容器 `/etc/myfw/ca`：

- **自动生成**：首次 `docker compose up` 时，容器入口脚本 `gen-ca-entrypoint.sh`
  自动生成 `ca.pem / ca.key / server.crt / server.key`（server 证书 SAN 取自
  `.env` 的 `MYFW_SAN`）；之后容器重建复用，已注册 Agent 不失效。
- **预生成**（可选，等效）：`CA_DIR=deploy/docker/dev-ca SAN=... ./scripts/gen-ca.sh`。

⚠ ca.key 为 CA 私钥，请勿外泄、勿删除；删除 = 换信任根 = 所有 Agent 需重新 bootstrap。
