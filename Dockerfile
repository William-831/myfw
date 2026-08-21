# Controller 镜像构建（多阶段：前端 + Go 二进制 + 运行时）
# 配置随镜像内置（敏感值走 .env 注入,配置内无机密）;
# CA 证书与 Agent 二进制运行时挂载,不打入镜像。
# 构建：docker compose -f docker-compose.prod.yml build（或 docker build -f deploy/docker/Dockerfile .）

# ---- 阶段1：前端构建 ----
FROM docker.m.daocloud.io/library/node:20-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build                # 输出 /web/dist（index.html + assets/）

# ---- 阶段2：Controller 编译（vendor 离线编译） ----
FROM ocker.m.daocloud.io/library/golang:1.26.5-alpine3.24 AS ctrl
WORKDIR /src
ARG VERSION=dev
COPY go.mod go.sum ./
COPY vendor/ ./vendor/
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY api/ ./api/
COPY proto/ ./proto/
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /usr/local/bin/myfw-controller ./cmd/controller

# ---- 阶段3：运行时 ----
FROM docker.m.daocloud.io/library/alpine:3.24
RUN apk add --no-cache openssl
COPY --from=ctrl /usr/local/bin/myfw-controller /usr/local/bin/myfw-controller
# 前端静态资源（server.go 提供 /assets 与 index.html）
COPY --from=web /web/dist /var/www/myfw
# 自动生成 CA 的入口脚本
COPY deploy/docker/gen-ca-entrypoint.sh /usr/local/bin/gen-ca-entrypoint.sh
# 生产配置随镜像内置(CMD --config 指向此处;敏感值全部由 .env 注入,文件内无机密;
# 如需自定义参数:改 deploy/docker/configs/controller.prod.example.yaml 后重建镜像)
COPY deploy/docker/configs/controller.prod.example.yaml /etc/myfw/config.yaml
RUN chmod +x /usr/local/bin/gen-ca-entrypoint.sh && \
    mkdir -p /etc/myfw/ca /data
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/gen-ca-entrypoint.sh"]
CMD ["--config", "/etc/myfw/config.yaml"]
