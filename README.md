# MYFW · Linux 防火墙策略管理平台

集中管理多节点 Linux iptables/nftables 的云原生平台。Controller（Web + gRPC）集中编排，Agent（裸机 systemd）落地执行，规则收敛在 `MYFW` 命名空间，不动 DOCKER/KUBE/用户手工规则。

```
[Web UI] --HTTP--> [Controller] --gRPC(mTLS)--> [Agent] --iptables--> [MYFW 链]
                         |
                   [MySQL/SQLite]
```

## 核心特性

- **两级策略模型**：策略模板（可复用骨架）+ 节点实例（独立参数快照），模板修改不影响已下发实例（drift 检测 + 手动/一键同步）
- **规则所有权隔离**：三层链结构 `系统链 -> MYFW 父链 -> 策略组子链`，只管 MYFW 命名空间，不碰 DOCKER/KUBE/用户链
- **保护期回滚**：下发后进入保护期，可确认或回滚；超时自动回滚，Agent 保留变更前快照；保护期内新动作自动**合并接管**旧任务（防抖，先 CAS 后执行）
- **watchdog 自愈**：Agent 定期检测期望态 hash，drift 时主动请求 Controller 重新下发，抗 docker/k8s 重启导致的 jump 错乱
- **漂移治理**：drift 来源分类（外部篡改 / 规则删除 / 重启丢失 / 未指定），配置侧字段级 diff 预览 + 一键同步全部
- **规则活性**：基于命中统计的死规则判定（超 3 天零命中），列表打标 + 一键清理
- **流量仿真**：单条策略预演引擎，生成自然语言结论 + 逐步骤 iptables 命令预览（打标 → 白名单放行 → 兜底 DROP 全链路）
- **规则库版本档案**：节点规则期望态版本化（RevNo 递增 + 保留最近 30 份），历史回滚走保护期
- **mTLS + HMAC**：gRPC 双向 TLS + HMAC 防重放，证书自动签发与续签
- **地址组 / 标记**：ipset 地址组（白/黑名单，支持 CIDR/范围自动展开为单 IP）、MARK 白名单拦截（打标 + 放行 + 兜底 DROP）
- **模板治理**：模板修改只影响未下发实例，同步时保留实例非空定制字段（如源 IP），MARK 引用强校验（值须已定义）
- **审计留痕**：所有变更写入审计日志，支持保护期变更仪表盘；规则库版本档案可回滚
- **专家终端**：白名单受限的裸 iptables 命令执行通道（不退化为 webshell）

## 技术栈

Go 1.26（Gin + gRPC + GORM + slog）+ Vue 3（Element Plus + Pinia + Vite）+ SQLite(dev)/MySQL(prod) + iptables/nftables

## 快速开始

### 1. 部署 Controller（Docker）

```bash
# 准备配置
cp deploy/docker/.env.example .env                          # 填入 DB DSN / HMAC 密钥
cp configs/controller.prod.example.yaml config.yaml

# 生成 CA（Controller 与 Agent mTLS 信任根）
mkdir -p dev-ca && cd dev-ca
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem -subj "/CN=MYFW CA"
cd ..

# 拉取镜像并启动（镜像仓库地址待定，替换 <registry>）
docker pull <registry>/myfw-controller:v1.1
docker compose -f docker-compose.prod.yml up -d
```

> 镜像也可本地构建：`docker build -t myfw-controller:v1.1 -f deploy/docker/Dockerfile.compose .`

健康检查：`curl http://localhost:8080/healthz` 返回 `{"status":"ok"}`

### 2. 安装 Agent（被管节点）

```bash
# 在 Controller Web UI 创建节点，获取 bootstrap token，然后在被管节点执行：
export MYFW_CONTROLLER=controller.example.com:9090
export MYFW_BOOTSTRAP_TOKEN=<token>
curl -fsSL https://controller.example.com:8080/download/agent/install-agent.sh | bash
```

或手动安装：下载 `myfw-agent` 二进制 + `deploy/systemd/myfw-agent.service`，配置 `/etc/myfw-agent/agent.yaml` 后 `systemctl enable --now myfw-agent`。

### 3. 使用

1. 打开 Web UI（`http://controller:8080`）
2. **策略组**：创建自定义子链（如 `acl-forward`，挂到 `MYFW-FORWARD`）
3. **地址组 / 标记**：维护 ipset 白名单、MARK 标记值
4. **节点策略**：为节点新建策略实例（选组 + 动作 + 协议/端口），下发
5. 下发后进入保护期，验证无误后点"确认"，误操作可"回滚"

## 配置

| 文件 | 说明 |
|------|------|
| `deploy/docker/.env.example` | 环境变量模板（DB DSN、HMAC 密钥），复制为 `.env` |
| `configs/controller.prod.example.yaml` | 生产配置（监听/TLS/连接池/审计保留），复制为 `config.yaml` |
| `docker-compose.prod.yml` | 生产编排（端口/卷挂载/重启策略） |
| `/etc/myfw-agent/agent.yaml` | Agent 配置（Controller 地址/TLS/bootstrap token） |

**关键环境变量**：
- `MYFW_DB_DRIVER` / `MYFW_DB_DSN`：数据库（`mysql` 或 `sqlite`），生产用 MySQL/OceanBase
- `MYFW_HMAC_SECRET`：HMAC 密钥（生产必须固定，否则重启后 Agent session 失效）

## 目录结构

```
cmd/controller/         Controller 入口
cmd/agent/              Agent 入口
internal/controller/    compiler(编译) policy(CRUD) server(HTTP路由)
                        task(状态机) stream(gRPC) audit(审计) pki(证书)
internal/agent/         bootstrap capability conn driver(iptables/nftables)
                        handler watchdog
internal/model/         数据模型（GORM）
internal/security/      mTLS/HMAC/会话
web/                    Vue 3 + Element Plus + Vite 前端
deploy/                 Dockerfile / systemd / 模板
docs/                   设计文档
```

## 开发

```bash
# 后端测试
go test ./...

# 前端构建
cd web && npm install && npm run build

# 交叉编译
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o myfw-controller ./cmd/controller
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o myfw-agent ./cmd/agent
```

## 文档

| 文档 | 内容 |
|------|------|
| [docs/design.md](docs/design.md) | 架构、数据模型、MYFW 链结构、状态机 |
| [docs/development-plan.md](docs/development-plan.md) | 开发方案与里程碑 |
| [docs/robustness-design.md](docs/robustness-design.md) | 健壮性改造（校验统一/在线状态/保护期回滚） |
| [docs/template-io-design.md](docs/template-io-design.md) | 模板库导入导出设计 |

> 更多阶段设计文档见 `Claudemissing/`（架构决策、修复方案、部署记录）。

## 版本

- **v1.2**（2026-08-17）：漂移治理与治理工具箱。配置侧 drift 字段级 diff 预览 + 一键同步；运行时 drift 来源分类（篡改/删除/重启丢失）；规则活性死规则判定；流量仿真预演引擎（自然语言结论 + iptables 命令预览）；规则库版本档案与回滚；保护期动作合并接管（CAS 防竞争）；模板治理（同步选择性覆盖、MARK 引用强校验、地址组 IP 范围展开）；前端响应优化（缓存失效修复 + 实时轮询 + 乐观更新 + 意图化待确认展示）。
- **v1.1**（2026-08-07）：首个正式发行版。策略创建/下发链路审查修复（方向字段收口、`IsMarkWhitelist` 单一判定、删 `MarkACLGroupID` 死字段、命令预览 `MYFW-` 前缀修复）；iptables `Snapshot/Restore` 覆盖自定义组链（保护期回滚完整性）；Controller sync 请求触发重新下发（消除 drift 死循环）；agent driver 测试适配两级模型。

## 许可

私有项目，版权所有。
