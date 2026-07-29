# 开发方案

> 版本：v0.3
> 更新日期：2026-07-28
> 配套文档：[design.md](./design.md)、[deployment.md](./deployment.md)、[progress.md](./progress.md)

---

## 目录

- [1. 总体原则](#1-总体原则)
- [2. 项目目录结构](#2-项目目录结构)
- [3. 里程碑与阶段划分](#3-里程碑与阶段划分)
- [4. 各阶段详情](#4-各阶段详情)
- [5. Git 工作流](#5-git-工作流)
- [6. 质量基线](#6-质量基线)
- [7. 依赖清单](#7-依赖清单)

---

## 1. 总体原则

1. **契约先行**：先定 gRPC proto 和数据库 schema，再写业务代码。协议一旦确定，Controller 和 Agent 可以并行开发。
2. **可运行优先**：每个阶段结束时，`main` 分支必须能编译、能启动、能被下一阶段接手。宁可功能少，不留半成品。
3. **开发环境 SQLite**：所有阶段都在 SQLite 上跑通，OB 只在联调/预发时切入，避免早期强依赖外部资源。
4. **Agent 静态编译**：从第一天起就用 `CGO_ENABLED=0`，防止后期出现"本地能跑，装机不能跑"的坑。
5. **安全基线不妥协**：mTLS、审批流、快照回滚是核心，不能为了赶进度砍掉。功能可以砍，安全不能砍。
6. **所有产出物入 git**：设计文档、代码、脚本、配置模板、迁移文件全部纳入版本管理；构建产物（`dist/`、`*.db`、证书）走 `.gitignore`。

---

## 2. 项目目录结构

以下是最终形态。实际开发按阶段逐步创建，不需要一次性建齐。

```
go-iptablesops/                  # 目录名；Go 模块名为 iptables-tool（见 go.mod）
├── docs/                         # 设计 / 部署 / 开发方案 / 进度
│   ├── design.md
│   ├── deployment.md
│   ├── development-plan.md
│   └── progress.md
├── proto/                        # gRPC 协议定义
│   └── myfw/
│       └── v1/
│           ├── common.proto
│           ├── registration.proto
│           ├── rule.proto
│           └── stream.proto
├── api/                          # protoc 生成物,入 git 便于 IDE 索引
│   └── myfw/v1/*.pb.go
├── cmd/
│   ├── controller/               # Controller 主入口
│   │   └── main.go
│   └── agent/                    # Agent 主入口
│       └── main.go
├── internal/
│   ├── config/                   # Controller 配置加载（env > file > default）
│   ├── db/                       # GORM Driver 切换 + 迁移（SQLite/MySQL，无静默降级）
│   ├── model/                    # 实体定义（含 IptablesRule 规则持久化模型）
│   ├── pki/                      # 私有 CA / 证书签发 / 指纹校验
│   ├── security/                 # 通信安全：会话令牌 + HMAC + 防重放 + IP 钉扎 + 证书轮换
│   ├── controller/               # Controller 业务模块
│   │   ├── server/               #   Gin + gRPC 编排 + REST 路由（按域拆分 *_routes.go）
│   │   ├── auth/                 #   用户认证
│   │   ├── asset/                #   节点资产管理
│   │   ├── policy/               #   策略 CRUD + 版本
│   │   ├── compiler/             #   Rule Compiler
│   │   ├── task/                 #   任务调度 + Coordinator 状态机
│   │   ├── registration/         #   节点注册
│   │   ├── stream/               #   AgentStream 服务端（双向流）
│   │   ├── audit/                #   审计日志
│   │   └── alerting/             #   告警（webhook）
│   ├── agent/                    # Agent 业务模块
│   │   ├── bootstrap/            #   首次注册 + 身份派生 + CSR
│   │   ├── config/               #   Agent 配置加载
│   │   ├── conn/                 #   gRPC mTLS 长连接 + 重连
│   │   ├── capability/           #   能力探测
│   │   ├── driver/               #   Driver 接口 + iptables/nftables 实现（含 fakeexec）
│   │   ├── handler/              #   任务执行（Snapshot/Apply/Confirm/Rollback）
│   │   ├── watchdog/             #   漂移检测
│   │   └── collector/            #   状态采集（CPU/内存/网络/连接）
├── web/                          # Vue3 前端（Vite + Element Plus）
│   ├── src/
│   │   ├── api/                  #   接口封装
│   │   ├── layout/               #   布局
│   │   ├── router/               #   路由
│   │   └── views/                #   页面（Login/Nodes/Dashboard/Approve/Audit/Policies）
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
├── configs/
│   ├── controller.dev.yaml
│   └── controller.prod.example.yaml
├── deploy/
│   ├── docker/
│   │   └── Dockerfile.controller # Controller 镜像构建（docker-compose 由部署方维护，见 deployment.md）
│   └── systemd/
│       ├── myfw-agent.service
│       └── install-agent.sh
├── scripts/
│   ├── gen-ca.sh                 # 开发用 CA 生成
│   ├── proto-gen.sh              # protoc 一把梭
│   └── build-agent.sh            # Agent 多平台交叉编译
├── test/
│   ├── integration/              # 端到端集成测试
│   └── fixtures/                 # 测试数据
├── .gitignore
├── .editorconfig
├── Makefile
├── go.mod
├── go.sum
├── LICENSE                       # 待定（MIT / Apache-2.0），暂缓
└── README.md
```

---

## 3. 里程碑与阶段划分

按"每个阶段结束都是一个能跑的东西"来切分，共 13 个阶段：

| 阶段 | 主题 | 交付物 | 依赖 |
|---|---|---|---|
| **M0** | 项目脚手架 | Git 仓库、目录、Makefile、CI 空壳、README | — |
| **M1** | 契约层（Proto + DB Schema） | gRPC proto、GORM model、DB 迁移双 Driver 跑通 | M0 |
| **M2** | Controller 骨架 | 空 Controller 能启动、监听 8080/9090、加载 mTLS | M1 |
| **M3** | PKI + 节点注册 | 首个 Agent 能 bootstrap 注册、Web 上审核入库 | M2 |
| **M4** | Agent 骨架 + 能力探测 | Agent 二进制、systemd unit、心跳、能力上报 | M3 |
| **M5** | Firewall Driver + IptablesDriver | MYFW 链创建、跳转、Hash 校验、单机可下发规则 | M4 |
| **M6** | 策略模型 + Rule Compiler | Web 上建策略 → 编译 → 下发到 Agent | M5 |
| **M7** | 变更审批 + 快照 + 自动回滚 | 完整变更流程闭环 | M6 |
| **M8** | Watchdog 漂移检测 | 外部改 MYFW 规则能被检测并告警 | M7 |
| **M9** | NftablesDriver | 支持 nftables 后端的节点 | M5 |
| **M10** | 状态采集 | 网卡流量、连接数、规则命中数据接入 | M6 |
| **M11** | Web 前端 | Vue3 控制台可用 | M2+ |
| **M12** | 审计 / 告警 / 观测完善 | 审计导出、告警渠道、Prometheus 指标 | M7 |
| **M13** | 打包分发 | Controller 镜像、Agent 一键安装脚本、多平台产物 | M4+ |

**串行 / 并行关系**：M0→M1→M2→M3→M4 是硬串行；M5/M6/M7 主线内串行；M8/M9/M10/M11 可与主线并行推进；M12/M13 收尾。

---

## 4. 各阶段详情

### M0. 项目脚手架

**目标**：给后续所有阶段一个可用的开发环境。

**任务**：

- [ ] `git init`，写 `.gitignore`（Go / IDE / OS / dist/ / *.db / dev-ca/ / .env）
- [ ] `README.md`：一段话说明项目 + 指向 docs/
- [ ] `go mod init iptables-tool`（纯本地路径，后续需要发布时再改为 `github.com/<owner>/iptables-tool`）
- [ ] 建目录树骨架（每个空目录放 `.gitkeep`）
- [ ] `Makefile`：`build`、`test`、`lint`、`proto`、`clean`、`dev-controller`、`dev-agent`
- [ ] `.editorconfig`
- [ ] `LICENSE`（默认 MIT，你如果想用别的告诉我）
- [ ] 首次 commit

**完成标志**：`make build` 能通过（即使内容是空 main）。

---

### M1. 契约层（Proto + DB Schema）

**目标**：双端"合同"到位，之后可以并行开发。

**任务**：

- [ ] 引入依赖：`google.golang.org/grpc`、`google.golang.org/protobuf`、`gorm.io/gorm`、`gorm.io/driver/mysql`、`modernc.org/sqlite`（无 CGO 的 SQLite）
- [ ] `proto/myfw/v1/*.proto`：
  - `common.proto`：`Node`、`Capability`、`Timestamp`
  - `registration.proto`：`Register`、`Heartbeat`、`RenewCert`
  - `rule.proto`：标准化规则对象、Driver 无关
  - `stream.proto`：双向 stream 消息（任务下发、结果回传、状态推送）
- [ ] `scripts/proto-gen.sh` + Makefile 目标 `make proto`
- [ ] `internal/model/`：所有实体的 GORM 结构体
  - `Node`、`NodeCapability`、`Policy`、`PolicyVersion`、`Rule`、`Task`、`Approval`、`Snapshot`、`AuditLog`、`Certificate`
- [ ] `internal/db/db.go`：`OpenFromEnv()` 根据 `MYFW_DB_DRIVER` 切换 SQLite / MySQL
- [ ] 迁移方案：AutoMigrate 兜底 + `internal/db/migrations/*.sql` 版本化脚本
- [ ] 单测：SQLite 和 MySQL（用 dockertest 或 testcontainers）都跑一遍迁移 + 基础 CRUD

**完成标志**：`go test ./internal/db/...` 双 Driver 都绿。

---

### M2. Controller 骨架

**目标**：Controller 能起来，什么业务都没有，但通道通了。

**任务**：

- [ ] `internal/config/`：加载 YAML + 环境变量覆盖（用 viper 或手写）
- [ ] `configs/controller.dev.yaml`：开发默认配置
- [ ] `internal/controller/server/`：
  - 启动 Gin (Web)
  - 启动 gRPC server，加载 mTLS（`client_auth: require_and_verify`）
  - 优雅关闭
- [ ] `scripts/gen-ca.sh`：开发用一键生成 CA + 服务端证书
- [ ] `cmd/controller/main.go`：解析 flag、初始化 log、启动 server
- [ ] 一个健康检查 REST 接口：`GET /healthz`
- [ ] 一个空的 gRPC 方法用于 smoke test

**完成标志**：`make dev-controller` 起进程，`curl` 打 `/healthz` 返回 ok，用 `grpcurl` 带客户端证书能 ping 到 gRPC。

---

### M3. PKI + 节点注册

**目标**：Agent 能通过 bootstrap token 注册进来，管理员能在 API 层面审核（前端 M11 才做，此阶段用 curl / REST 完成）。

**任务**：

- [ ] `internal/pki/`：
  - 加载 CA
  - 签发客户端证书（CN 或 URI SAN 携带 node_id）
  - 计算证书指纹（SHA-256 DER）
  - 校验证书 + 指纹绑定
- [ ] Controller 接口：
  - `POST /api/v1/nodes/bootstrap`：管理员生成一次性 bootstrap_token（15min TTL）
  - `POST /api/v1/nodes/pending`：列出 PENDING 节点
  - `POST /api/v1/nodes/:id/approve`：审核通过
  - gRPC `Register(bootstrap_token, csr, candidate_id, fingerprint, capabilities)` → 返回签发好的证书 + 最终 node_id
- [ ] 数据表：`nodes`、`bootstrap_tokens`、`certificates`
- [ ] gRPC server 在每次连接上校验：证书链 + node_id 匹配 + 指纹匹配
- [ ] 审计事件写入：注册、审核、指纹不匹配拒绝

**完成标志**：用 openssl 手工模拟 Agent 走完注册 → PENDING → 审核 → 用签发证书连 gRPC 成功。

---

### M4. Agent 骨架 + 能力探测

**目标**：一个二进制在 Linux 上装完就能连 Controller 心跳。

**任务**：

- [ ] `cmd/agent/main.go`：flag、配置加载、日志
- [ ] `internal/agent/bootstrap/`：
  - 生成 / 读取 `/var/lib/myfw-agent/node.id`
  - 生成私钥 + CSR
  - 用 bootstrap_token 走 gRPC Register
  - 落盘证书，清空配置中的 token
- [ ] `internal/agent/conn/`：gRPC 双向 stream 长连接 + 断线重连 + 心跳
- [ ] `internal/agent/capability/`：探测发行版、iptables 版本、iptables backend、nft 支持、Docker、K8s 等
- [ ] `scripts/build-agent.sh`：`CGO_ENABLED=0` linux/amd64 + linux/arm64 静态编译
- [ ] `deploy/systemd/myfw-agent.service` 模板
- [ ] `deploy/systemd/install-agent.sh`：对齐 `deployment.md § 5.3` 的一键安装脚本

**完成标志**：在一台 Ubuntu VM 上执行安装脚本，Agent 起来，Controller 侧能看到心跳；`kill` Agent 再启动，`node_id` 不变。

---

### M5. Firewall Driver + IptablesDriver

**目标**：单个 Agent 能被下发一条 iptables 规则并落到 MYFW 链。

**任务**：

- [ ] `internal/agent/driver/driver.go`：定义接口
  ```go
  type Driver interface {
      Init(ctx context.Context) error           // 建立 MYFW 命名空间 + 跳转
      Apply(ctx context.Context, rules []Rule) error
      Diff(ctx context.Context) (DiffResult, error)
      Snapshot(ctx context.Context) (Snapshot, error)
      Restore(ctx context.Context, s Snapshot) error
      Hash(ctx context.Context) (string, error)
      Teardown(ctx context.Context) error       // 清理 MYFW(仅下线用)
  }
  ```
- [ ] `internal/agent/driver/iptables/`：
  - 创建 6 条 MYFW 链：filter `MYFW-INPUT`/`MYFW-OUTPUT`/`MYFW-FORWARD`、nat `MYFW-PREROUTING`/`MYFW-POSTROUTING`、mangle `MYFW-MANGLE`
  - 在系统链 `INPUT`/`OUTPUT`/`FORWARD`/`PREROUTING`/`POSTROUTING` 顶部插入跳转规则（ensureJump 顶部精准 + 幂等重排，见 design.md §8）
  - Apply：把标准规则对象翻译成 iptables 命令，只操作 MYFW 命名空间
  - Diff：读取当前 MYFW 内容，与期望态对比
  - Snapshot / Restore：用 `iptables-save` / `iptables-restore`，但仅限 MYFW 命名空间
  - Hash：对 MYFW 命名空间内规则做归一化 SHA-256
- [ ] 一条端到端 gRPC 任务：Controller 下发规则 → Agent 执行 → 结果回传
- [ ] 集成测试：在容器/VM 里跑，验证 `iptables -S` 能看到 MYFW-* 链和规则

**完成标志**：手工调用 Controller REST 下发一条"允许 10.0.0.0/24 访问本机 22 端口"的规则，在目标 Agent 上 `iptables -S MYFW-INPUT` 能看到。

---

### M6. 策略模型 + Rule Compiler

**目标**：管理员写抽象策略，系统自动编译成规则下发。

**任务**：

- [ ] `internal/controller/policy/`：策略 CRUD、版本化
- [ ] `internal/controller/compiler/`：策略 → 标准规则对象；决策规则位置 / 优先级
- [ ] `internal/controller/task/`：把编译结果打包成 Task 下发给相关 Agent
- [ ] Web API（无前端也能用）：
  - `POST /api/v1/policies`
  - `GET /api/v1/policies`
  - `POST /api/v1/policies/:id/apply`（触发编译 + 下发）

**完成标志**：REST 调用一个 apply 接口，自动完成"编译 → 下发 → 落到 Agent iptables"全链路。

---

### M7. 变更审批 + 快照 + 自动回滚

**目标**：所有变更走审批，Agent Apply 前快照，超时未确认自动回滚。

**任务**：

- [ ] Approval 数据模型 + REST：submit / list / approve / reject
- [ ] Task 状态机：`draft → pending_approval → approved → dispatching → applying → confirm_wait → confirmed / rolled_back`
- [ ] Agent 侧：Apply 前 `driver.Snapshot()`，Apply 后启动确认保护定时器；超时未确认自动 `driver.Restore()`
- [ ] Controller 侧：Apply 成功后需要在保护期内下发一次 confirm
- [ ] 全过程写审计日志

**完成标志**：故意提交一个错规则 → 审批通过 → Apply → Controller 不 confirm → 到期 → Agent 自动回滚 → iptables 恢复到 Apply 前状态。

---

### M8. Watchdog 漂移检测

**目标**：外部修改 MYFW 内规则时能检测并告警。

**任务**：

- [ ] `internal/agent/watchdog/`：定期计算 MYFW 命名空间 Hash，与 Controller 存的期望 Hash 对比
- [ ] 漂移事件上报 + 审计
- [ ] 配置：自动恢复 or 仅告警

**完成标志**：Agent 起来后手工在宿主机 `iptables -D MYFW-INPUT 1`，30 秒内 Controller 收到告警。

---

### M9. NftablesDriver

**目标**：现代 Linux 发行版走 nftables。

**任务**：

- [ ] `internal/agent/driver/nftables/`：MYFW table + chain + hook
- [ ] 能力探测优先级：如果两者都可用，让 Controller 端有开关决定选哪个（默认按发行版年份）
- [ ] 联调：策略同一份，两种 Driver 都能达到等价效果

---

### M10. 状态采集

**目标**：Web 上能看到实时流量 / 连接 / 命中。

**任务**：

- [ ] Netlink / /proc / conntrack 采集
- [ ] 数据上报格式统一
- [ ] Controller 侧聚合 + 存 OB

---

### M11. Web 前端

**目标**：可视化管理。

**任务**：

- [ ] `web/` 目录用 Vite + Vue3 + TS + Element Plus 初始化
- [ ] 页面：登录、节点列表、待审核节点、策略管理、审批中心、变更历史、审计日志、节点详情（含专家模式）
- [ ] Controller 反代前端静态资源，或独立 Nginx

---

### M12. 审计 / 告警 / 观测完善

**任务**：

- [ ] 审计日志导出（CSV / JSON）
- [ ] Prometheus 指标：`myfw_agent_up`、`myfw_task_total`、`myfw_drift_total`、`myfw_apply_duration_seconds` 等
- [ ] 告警渠道（webhook / 邮件，任选一）

---

### M13. 打包分发

**任务**：

- [ ] Controller Docker 镜像：多阶段构建，distroless 或 alpine
- [ ] Agent 产物：`.tar.gz` 打包 `myfw-agent` + `install.sh` + `myfw-agent.service`
- [ ] （可选）`.deb` / `.rpm`
- [ ] GitHub Actions / 类似 CI 自动构建 tag 版本

---

### M14. 地址组 + ipset/nft set + mark 联动（已实现）

**目标**：白/黑名单多 CIDR + mark 标记联动，管控 Docker 暴露端口流量。

**已交付**：

- [x] `AddressGroup` model + CRUD API + 前端地址组管理页
- [x] proto 扩展（`CompiledRule` +`source_group`/`destination_group`/`match_mark`，`RuleSet` +`sets`，新增 `AddressSet`）
- [x] compiler `CompileForNode` 返回 `(rules, sets)`；driver `Apply(*RuleSet)` 原子下发 sets（iptables `ipset` + nft `set`）
- [x] `compileRule` 加 `-m set`/`-m mark`；nft 补 `ACTION_MARK`；实测 ipset + mark+白名单联动在节点生效

### M14+. MYFW 收敛理念落地（P1-P4）

- [~] **P1** ensureJump 顶部精准重排 + ESTABLISHED 放行（重排已实现，ESTABLISHED 进行中）
- [ ] **P2** 节点直操作收敛 MYFW（拒绝直接操作内置链）
- [ ] **P3** watchdog jump 顺序自愈（抗 docker/k8s 重启）
- [ ] **P4** 自定义链 web 管理（`CustomChain` model + driver 动态子链 + 策略指定链）

---

## 5. Git 工作流

**分支模型**（简化版，个人项目够用）：

- `main`：始终可编译、可跑。每个阶段结束打一个 tag（`v0.1.0-m0`、`v0.1.0-m1`...）
- `feat/<short-name>`：单个阶段/特性分支，完成后合并回 `main`
- `fix/<short-name>`：紧急修复

**Commit 规范**（Conventional Commits 简化版）：

```
<type>(<scope>): <subject>

<body>
```

- `type`：`feat`、`fix`、`docs`、`chore`、`refactor`、`test`、`build`
- `scope`：`controller`、`agent`、`driver`、`proto`、`db`、`ci`、`docs`...
- 例：`feat(agent): add capability detection module`

**每个阶段结束的动作**：

1. 在对应特性分支上完成开发
2. 合并回 `main`
3. 更新 `docs/progress.md`：勾选完成项 + 补一行「里程碑达成」记录
4. 打 tag：`git tag -a v0.1.0-m2 -m "Milestone 2: Controller skeleton"`

---

## 6. 质量基线

每个 PR / 合并前必须过的：

- `make lint`：`golangci-lint run`
- `make test`：单测全绿
- `make build`：Controller 和 Agent 都能编译（Agent 必须验证是 statically linked）
- 涉及 proto 变更：`make proto` 已重新生成，生成物入 commit
- 涉及数据库 schema：迁移脚本已加入 `internal/db/migrations/`

---

## 7. 依赖清单

预计使用的关键库（版本按开发时最新稳定版）：

**后端**：

| 库 | 用途 |
|---|---|
| `github.com/gin-gonic/gin` | Web 框架 |
| `google.golang.org/grpc` | gRPC |
| `google.golang.org/protobuf` | protobuf |
| `gorm.io/gorm` | ORM |
| `gorm.io/driver/mysql` | MySQL 协议驱动（连 OB） |
| `modernc.org/sqlite` | 开发用 SQLite（纯 Go 免 CGO） |
| `gorm.io/driver/sqlite` 的替代 | 上面这个包配合 `github.com/glebarez/sqlite` 让 GORM 用免 CGO 的 sqlite |
| `github.com/spf13/viper` 或 `github.com/knadh/koanf` | 配置加载 |
| `github.com/spf13/cobra` | CLI 参数（可选，也可以只用标准 flag） |
| `go.uber.org/zap` 或 `log/slog` | 日志（推荐 slog） |
| `github.com/google/uuid` | UUID |
| `github.com/prometheus/client_golang` | 指标 |

**Agent 侧防火墙操作**（挑一套）：

- iptables：`github.com/coreos/go-iptables` 或直接 `os/exec` 调 `iptables` 二进制
- nftables：`github.com/google/nftables`
- Netlink：`github.com/vishvananda/netlink`

**前端**：Vue3 + TypeScript + Vite + Element Plus + Pinia。

---

## 附：下一步

M0 完成后立即启动 M1，双方向并行度低，但后续 M3+ 之后 Controller 主线和 Agent 主线可以拆两条分支同时推。
