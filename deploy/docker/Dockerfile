# Controller 镜像构建（多阶段：前端 + Go 二进制 + 运行时）
# CA 证书与 Agent 二进制运行时挂载，不打入镜像。
# 构建：docker build -t myfw-controller:v0.3.0 -f deploy/docker/Dockerfile.compose .

# ---- 阶段1：前端构建 ----
FROM  docker.m.daocloud.io/library/node:20-alpine AS web
WORKDIR /web
COPY /web/package.json web/package-lock.json ./
RUN npm ci
COPY /web/ ./
RUN npm run build                # 输出 /web/dist（index.html + assets/）

# ---- 阶段2：Controller 编译（vendor 离线编译） ----
FROM docker.m.daocloud.io/library/golang:1.26.5-alpine3.24 AS ctrl
WORKDIR /src
ARG VERSION=dev
COPY /go.mod go.sum ./
COPY /vendor/ ./vendor/
COPY /cmd/ ./cmd/
COPY /internal/ ./internal/
COPY /api/ ./api/
COPY /proto/ ./proto/
RUN CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /usr/local/bin/myfw-controller ./cmd/controller

# ---- 阶段3：运行时 ----
FROM docker.m.daocloud.io/library/alpine:3.24
COPY --from=ctrl /usr/local/bin/myfw-controller /usr/local/bin/myfw-controller
# 前端静态资源（server.go 提供 /assets 与 index.html）
COPY --from=web /web/dist /var/www/myfw
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/myfw-controller"]
CMD ["--config", "/etc/myfw/config.yaml"]
