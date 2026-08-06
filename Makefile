# MYFW Makefile
# See docs/development-plan.md § 6 for the quality baseline these targets enforce.

# ---- Variables ----
VERSION      ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS      := -s -w -X main.version=$(VERSION)
GO           ?= go
DIST         := dist

# Agent must be statically linked (no CGO) so it runs on any Linux distro.
AGENT_ENV    := CGO_ENABLED=0

.DEFAULT_GOAL := help

# ---- Meta ----
.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ---- Build ----
.PHONY: build
build: build-controller build-agent ## Build both binaries for the host platform

.PHONY: build-controller
build-controller: ## Build the controller binary
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/myfw-controller ./cmd/controller

.PHONY: build-agent
build-agent: ## Build the agent binary (static, no CGO)
	$(AGENT_ENV) $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/myfw-agent ./cmd/agent

.PHONY: build-agent-linux
build-agent-linux: ## Cross-compile the agent for linux/amd64 and linux/arm64 (static)
	$(AGENT_ENV) GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/myfw-agent-linux-amd64 ./cmd/agent
	$(AGENT_ENV) GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(DIST)/myfw-agent-linux-arm64 ./cmd/agent

.PHONY: deploy-agent
deploy-agent: build-agent-linux ## 交叉编译 Agent 并部署到 ./agent/（供节点安装脚本 curl 下载）
	@mkdir -p agent
	cp $(DIST)/myfw-agent-linux-amd64 agent/myfw-agent-linux-amd64
	@echo "deploy-agent: ./agent/ 已就位，容器挂载后经 /download/agent/linux-amd64 提供"

# ---- Dev run ----
.PHONY: dev-controller
dev-controller: ## Run the controller locally against SQLite
	MYFW_DB_DRIVER=sqlite MYFW_DB_DSN=./dev.db $(GO) run ./cmd/controller --config configs/controller.dev.yaml

.PHONY: dev-agent
dev-agent: ## Run the agent locally (requires root for real firewall ops)
	$(GO) run ./cmd/agent --config dev-agent.yaml

# ---- Quality ----
.PHONY: test
test: ## Run unit tests
	$(GO) test ./...

.PHONY: lint
lint: ## Run golangci-lint (must be installed)
	golangci-lint run

.PHONY: fmt
fmt: ## Format all Go code
	$(GO) fmt ./...

.PHONY: vet
vet: ## Run go vet
	$(GO) vet ./...

# ---- Codegen ----
.PHONY: proto
proto: ## Regenerate protobuf/gRPC code
	./scripts/proto-gen.sh

# ---- CA (生产 mTLS) ----
.PHONY: gen-ca
gen-ca: ## 生成生产级 CA 与 server 证书（SAN="域名或IP" ./scripts/gen-ca.sh）
	./scripts/gen-ca.sh

# ---- Cleanup ----
.PHONY: clean
clean: ## Remove build artifacts and dev databases
	rm -rf $(DIST) dev.db dev.db-journal
