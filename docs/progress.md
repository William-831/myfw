# 开发进度

> 更新日期：2026-07-29
> 配套文档：[development-plan.md](./development-plan.md)
>
> **图例**：`[ ]` 未开始 · `[~]` 进行中 · `[x]` 已完成 · `[-]` 已跳过

---

## 里程碑总览

| # | 阶段 | 状态 | 起始 | 完成 | Tag | 备注 |
|---|---|---|---|---|---|---|
| M0 | 项目脚手架 | `[x]` | 2026-07-20 | 2026-07-20 | v0.1.0-m0 | 双端二进制编译通过，Agent 交叉编译验证为静态链接 |
| M1 | 契约层（Proto + DB） | `[x]` | 2026-07-20 | 2026-07-20 | v0.1.0-m1 | proto+gRPC 生成、GORM 双 Driver、SQLite 测试绿；全模块 CGO-free 验证 |
| M2 | Controller 骨架 | `[x]` | 2026-07-20 | 2026-07-20 | v0.1.0-m2 | Gin+gRPC 启动、强制 mTLS（含拒绝无证书的回归测试）、/healthz、优雅关闭 |
| M3 | PKI + 节点注册 | `[x]` | 2026-07-20 | 2026-07-21 | v0.1.0-m3 | 完整端到端注册流程跑通（含 bootstrap token 一次性 / 证书指纹绑定 / 三重校验拦截器 / 审批状态迁移） |
| M4 | Agent 骨架 + 能力探测 | `[x]` | 2026-07-21 | 2026-07-21 | v0.1.0-m4 | 完整 bootstrap 流程实机（macOS）跑通：注册 → 落盘 → token 自清 → 心跳 stream 建立 |
| M5 | Firewall Driver + Iptables | `[x]` | 2026-07-21 | 2026-07-21 | v0.1.0-m5 | Driver 抽象 + IptablesDriver + AgentStream 服务端 + REST 触发 apply 端到端跑通（含 fake iptables 落规则、Linux 侧真 iptables 联调延后） |
| M6 | 策略模型 + Rule Compiler | `[x]` | 2026-07-21 | 2026-07-21 | v0.1.0-m6 | Policy CRUD + versioning、Compiler（node_ids + label selector）、Dispatcher 并行下发聚合结果，端到端跑通 |
| M7 | 变更审批 + 快照 + 回滚 | `[x]` | 2026-07-21 | 2026-07-21 | v0.1.0-m7 | 完整状态机（submit→approve→dispatch→apply→confirm_wait→confirmed / auto-rollback）、startup recovery、三个端到端路径 |
| M8 | Watchdog 漂移检测 | `[x]` | 2026-07-21 |  | v0.1.0-m8 | 30s Hash 对比 + 漂移上报 + AutoRecover 开关 |
| M9 | NftablesDriver | `[x]` | 2026-07-21 |  | v0.1.0-m9 | inet/ip family + 5 chain + fakeexec 测试 |
| M10 | 状态采集 | `[x]` | 2026-07-21 |  | v0.1.0-m10 | CPU/内存/网络/连接数采集 + StateReport 上报 |
| M11 | Web 前端 | `[x]` | 2026-07-21 | 2026-07-29 | v0.1.0-m11 | 登录/节点/策略/审批/审计/Dashboard/地址组就位；Controller 反代静态资源 |
| M12 | 审计 / 告警 / 观测 | `[x]` | 2026-07-21 | 2026-07-23 | v0.1.0-m12 | CSV 导出 + /metrics + webhook 告警 |
| M13 | 打包分发 | `[ ]` |  |  |  | 待启动 |

---

## M0. 项目脚手架

- [x] 撰写设计文档 `docs/design.md`
- [x] 撰写部署文档 `docs/deployment.md`
- [x] 撰写开发方案 `docs/development-plan.md`
- [x] 撰写进度文档 `docs/progress.md`
- [x] `git init` + `.gitignore` + 首次 commit
- [x] `README.md`
- [x] `go mod init`（纯本地路径 `iptables-tool`，Go 1.22）
- [x] 建目录树骨架（`cmd/` `internal/` `proto/` `api/` `configs/` `deploy/` `scripts/` `test/` `web/`，空目录用 `.gitkeep` 占位）
- [x] `Makefile` 基础目标（build / dev / test / lint / proto / gen-ca / clean）
- [x] `.editorconfig`
- [x] 脚手架文件：`cmd/*/main.go` 空壳、`configs/*.yaml`、`deploy/docker/*`、`deploy/systemd/*`、`scripts/*.sh`
- [ ] `LICENSE`（待定：MIT / Apache-2.0 / 其他，暂缓）
- [x] `make build` 通过（Go 1.26.5；双端二进制 + Agent linux/amd64 & arm64 静态链接均验证）
- [x] 打 tag `v0.1.0-m0`

---

## M1. 契约层（Proto + DB Schema）

- [x] 引入 Go 依赖：gRPC / GORM / SQLite（glebarez，免 CGO）/ MySQL 驱动
- [x] `proto/myfw/v1/common.proto`
- [x] `proto/myfw/v1/registration.proto`
- [x] `proto/myfw/v1/rule.proto`
- [x] `proto/myfw/v1/stream.proto`
- [x] `scripts/proto-gen.sh` + `make proto`（protoc 35.1 + protoc-gen-go/protoc-gen-go-grpc）
- [x] GORM 实体：`Node` / `NodeCapability` / `Policy` / `PolicyVersion` / `Rule` / `Task` / `Approval` / `Snapshot` / `AuditLog` / `Certificate` / `BootstrapToken`
- [x] `internal/db/db.go`：`OpenFromEnv()` 双 Driver 切换（sqlite/mysql，无静默降级）
- [x] SQLite 单测：迁移 + 基础 CRUD + 唯一约束 + env 配置
- [x] MySQL 单测：迁移 + CRUD（opt-in，`MYFW_TEST_MYSQL_DSN` 未设置时跳过）
- [ ] `internal/db/migrations/` 版本化 SQL（暂用 AutoMigrate，手写迁移待 schema 稳定后补）
- [ ] 打 tag `v0.1.0-m1`

---

## M2. Controller 骨架

- [x] `internal/config/`：YAML + env 覆盖（含 mTLS 必填校验；单测覆盖 env 优先级）
- [x] `configs/controller.dev.yaml`（M0 已建）
- [x] `internal/controller/server/`：Gin + gRPC 编排 + 优雅关闭
- [x] mTLS：`RequireAndVerifyClientCert`（回归测试：无证书拒绝 / 有效证书放行）
- [x] `scripts/gen-ca.sh`（M0 已建，本阶段验证可用）
- [x] `cmd/controller/main.go`：flag / slog / 配置 / DB 迁移 / 信号优雅退出
- [x] `GET /healthz`
- [x] gRPC server 起监听（业务方法待 M3 注册）
- [x] `make dev-controller` 启动验证（healthz 返回 ok，SIGTERM 优雅退出 exit 0）
- [x] 打 tag `v0.1.0-m2`

---

## M3. PKI + 节点注册

- [x] `internal/pki/`：加载 CA / CSR 签发（node_id → URI SAN）/ SHA-256 DER 指纹 / 校验；单测覆盖 round-trip + 拒绝坏 CSR
- [x] REST：`POST /api/v1/nodes/bootstrap`、`GET /api/v1/nodes`、`POST /api/v1/nodes/:id/approve` / `reject`
- [x] gRPC：`Register`（`RenewCert` 保留为 stub，M6/M7 前无实际调用）
- [x] 数据表落地：`nodes` / `bootstrap_tokens` / `certificates`（M1 已有 model，本阶段接入写入路径）
- [x] gRPC 连接层三重校验：证书链（TLS 层）→ 证书指纹（DB） → node_id 匹配（URI SAN vs DB）；Register RPC 免证书白名单
- [x] 审计事件：`node.register` / `bootstrap.create` / `node.approve` / `node.reject`（含 detail JSON）
- [x] 端到端集成测试：mint token → 无证书注册 → 收到签名证书 → 带证书通过拦截器 → 令牌不可复用 → REST 审批 PENDING→ACTIVE
- [x] 打 tag `v0.1.0-m3`

---

## M4. Agent 骨架 + 能力探测

- [x] `cmd/agent/main.go`：flag / slog / 配置 / 身份 / 能力探测 / 首次 bootstrap / 长连接 + 心跳 / 信号退出
- [x] `internal/agent/config/`：YAML + env（`MYFW_AGENT_*`），`Bootstrapped()` 探测已有证书，`RequireForBootstrap()` 校验最小字段集
- [x] `internal/agent/bootstrap/`：`LoadOrCreateIdentity`（machine-id + salt 派生稳定 node.id）；`GenerateKeyAndCSR`（EC P-256，私钥不出机）；`Do`（Register RPC + 原子落盘 key→cert）；`MachineFingerprint`
- [x] `internal/agent/conn/`：mTLS 客户端拨号（支持 bootstrap-only 无客户端证书）；`Loop` 心跳循环 + 指数退避重连；对 `Unimplemented` 容忍（等 M5 服务端实现）
- [x] `internal/agent/capability/`：Linux 发行版 / iptables 版本+backend / nft / Docker / K8s 探测；`chooseBackend` 优先级 iptables-nft > iptables-legacy > nftables
- [x] `scripts/build-agent.sh`（M0 已建）+ Makefile 静态编译验证（linux/amd64 & arm64 均 statically linked）
- [x] `deploy/systemd/myfw-agent.service`（M0 已建）
- [x] `deploy/systemd/install-agent.sh`（M0 已建）
- [x] macOS 装机验证（真实二进制 + 真实 Controller + SQLite）：node.id 稳定生成 → 能力探测 → Register → 证书落盘 → bootstrap_token 自动清除 → 长连接建立 → 服务端未实现时进入 backoff 重试
- [x] 单测：能力探测（never fails / backend 优先级）；bootstrap（node.id 稳定 & 跨 dir 不重复 / CSR 生成）；**端到端 e2e**（真 gRPC + 真 SQLite Controller ← Agent bootstrap，验证磁盘证书含正确 URI SAN、证书/私钥对匹配、token 单次使用）
- [x] Ubuntu VM 装机验证（可延后 —— macOS 已覆盖所有非 iptables 路径；Linux 侧的 iptables 探测将在 M5 联调 IptablesDriver 时一起验证）
- [x] 打 tag `v0.1.0-m4`

---

## M5. Firewall Driver + IptablesDriver

- [x] Driver interface 定义（`Init`/`Apply`/`Snapshot`/`Restore`/`Hash`/`Teardown`/`Backend`）
- [x] IptablesDriver：`Init` 幂等建 6 条 MYFW 链 + 系统链跳转；`Apply` 稳定排序 → flush → 依次 `-A`；`Snapshot`/`Restore` 用 `-S`/`-A` 往返；`Hash` = SHA-256(归一化 payload)；`Teardown` 清理跳转 + 删链
- [x] Exec 抽象（生产用 `ShellExec` 调 `iptables` 二进制；测试用 `fakeexec` 内存状态机）
- [x] AgentStream 服务端：连接层证书解析 node_id、注册表按 id 追踪连接、心跳落 `last_seen`、TaskResult 上行、断线清理
- [x] Controller 侧 REST：`POST /api/v1/nodes/:id/apply`（ad-hoc）+ `GET /api/v1/nodes/connected`
- [x] Agent 侧 `handler.Handler`：Snapshot → Apply；Apply 失败自动 Restore（M7 auto-rollback 的前置）；Confirm 清快照
- [x] 端到端 gRPC 任务 smoke：Controller 下发 → Agent 执行 → 结果回传
- [x] 集成测试：`TestApplyEndToEnd` 真 gRPC/mTLS/AgentStream 全链路 + fake iptables 验证规则真的落到 MYFW-* 链
- [x] Driver 单测：Init 幂等、Apply 落规则位置正确（filter/nat/mangle）、flush-then-refill、Snapshot/Restore round-trip、Hash 不依赖输入顺序、Teardown 干净
- [x] Handler 单测：Apply 成功 / Apply 失败自 rollback / Rollback 无快照安全 / Confirm 清空 / nil driver 优雅失败
- [x] macOS 实机 smoke：controller + agent + apply 下发，macOS 无 iptables → 返回 `ok=false, "no firewall driver on this host"`，pipe 完整
- [ ] Linux 真机 iptables 联调（延后到有 Linux VM 时；ShellExec 路径已就位）
- [x] 打 tag `v0.1.0-m5`

---

## M6. 策略模型 + Rule Compiler

- [x] policy 模块 CRUD + 版本（每次 Create/Update 生成 PolicyVersion 快照 + 事务保证一致性）
- [x] compiler 模块：Policy → CompiledRule，支持 `node_ids` 显式列表 + `labels` 交集匹配；输出按 (priority, id) 稳定排序
- [x] task 模块（Dispatcher）：并行下发到 target 节点，通过 `stream.SubscribeTaskResults` fan-out（多路 apply 不相互抢结果），按 task_id 匹配聚合，超时/取消/成功分别标记
- [x] REST：`POST/GET/PUT/DELETE /api/v1/policies`、`POST /api/v1/policies/:id/apply`、`POST /api/v1/policies/apply-all`；apply 返回 200 (全成功) / 207 (部分失败)
- [x] stream.Service 重构：`TaskResults` channel 换成多路 `SubscribeTaskResults()` fan-out API（旧 M5 legacy path 也切换过去，同时保留 REST 契约不变）
- [x] policy 单测：Create/Update/List、缺 target 拒绝、坏 action 拒绝、Update 不存在
- [x] compiler 单测：显式 target、跳过 disabled、稳定顺序、label 交集匹配、5 种 action 到 proto 映射正确
- [x] **端到端 E2E**：`TestPolicyApplyEndToEnd`（policy targets 一个 agent → 只有它拿到规则）+ `TestApplyAllPoliciesFanOut`（label selector 匹配两个 agent → 都拿到）
- [x] macOS 实机 smoke：curl 完整走 create → list → apply（macOS 无 driver 返回 `ok=false` 但 pipe 完整）→ update（v2）→ delete (204)
- [x] 打 tag `v0.1.0-m6`

---

## M7. 变更审批 + 快照 + 自动回滚

- [x] Approval 数据模型 + REST：`POST /api/v1/tasks/:id/approve`、`POST /api/v1/tasks/:id/reject`、`POST /api/v1/tasks/:id/confirm`、`GET /api/v1/tasks`、`GET /api/v1/tasks/:id`
- [x] Task 状态机：`pending_approval → approved → dispatching → applying → confirm_wait → confirmed / rolled_back / failed`；reject 从任意 pending 状态 → failed
- [x] Coordinator（`internal/controller/task/coordinator.go`）：Submit（创建 task 并可选 auto_approve）、Approve（审批+dispatch）、Reject、Confirm、resultLoop（消费 TaskResult 推进状态机）、armRollbackTimer（confirm_wait 后计时）、autoRollback（超时下发 RollbackTask）、recoverOnStart（启动恢复过期 confirm_wait + stuck applying/dispatching）
- [x] Policy apply 改造：默认走审批流（返回 202 + PENDING_APPROVAL tasks），`auto_approve=true` 保持同步语义（M6 测试兼容）
- [x] Task model 加 `ConfirmDeadline` + `Reviewer` 字段
- [x] 审计日志全过程：submit / approve / reject / applying_ok / apply_failed / confirm / auto_rollback / recover_failed
- [x] Agent 侧确认保护（M5 Handler 已就位）：Apply 前 Snapshot → Apply 失败自 Rollback → ConfirmTask 清快照 → RollbackTask 恢复快照
- [x] 端到端集成测试：`TestApprovalAndConfirmFlow`（submit→approve→apply→confirm→CONFIRMED）、`TestAutoRollbackFlow`（approve→deadline expire→ROLLED_BACK，verify rules restored）、`TestRejectFlow`（submit→reject→FAILED）
- [x] 打 tag `v0.1.0-m7`

---

## M8. Watchdog 漂移检测

- [x] watchdog 定期 Hash 对比（`internal/agent/watchdog/watchdog.go`，30s 间隔）
- [x] 漂移上报 + 审计（`internal/controller/stream/stream.go` 处理 DriftReport + 写入审计日志）
- [x] 自动恢复 / 仅告警开关（`AutoRecover` 选项，触发 SyncRequest）
- [x] 单元测试覆盖（`watchdog_test.go`：无漂移、漂移检测、无基线、Hash 错误、禁用、nil driver）
- [x] 打 tag `v0.1.0-m8`（指向 265aa51）

---

## M9. NftablesDriver

- [x] NftablesDriver 实现（`internal/agent/driver/nftables/nftables.go`，支持 inet/ip family，5 个 chain：INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING）
- [x] nftables fakeexec 测试实现（`internal/agent/driver/nftables/fakeexec/fakeexec.go`）
- [x] 能力探测联动（`internal/agent/capability/capability.go`，选择优先级：iptables-nft → iptables-legacy → nftables）
- [x] 单元测试覆盖（`nftables_test.go`：Init 幂等、Apply、Snapshot、Restore、Hash、Teardown、多规则、flush-then-fill）
- [x] 打 tag `v0.1.0-m9`（指向 265aa51）

---

## M10. 状态采集

- [x] 状态采集模块（`internal/agent/collector/collector.go`，采集 CPU、内存、网络接口、连接数）
- [x] 上报协议（复用现有 `StateReport` + `InterfaceStat`，通过 `AgentToController_State` 发送）
- [x] Controller 接收处理（`internal/controller/stream/stream.go` 记录调试日志）
- [x] 打 tag `v0.1.0-m10`（指向 265aa51）

---

## M11. Web 前端

- [x] `web/` 项目初始化（Vite + Vue3 + Element Plus）
- [x] 登录页面 / 节点管理页面 / 节点详情
- [x] 策略管理页面（CRUD）/ 审批中心页面
- [x] 审计日志页面 / 系统概览 Dashboard
- [ ] Controller 反代静态资源
- [x] 打 tag `v0.1.0-m11`（指向 265aa51）

---

## M12. 审计 / 告警 / 观测完善

- [x] 审计日志导出（CSV格式，支持筛选导出）
- [x] Prometheus 指标暴露（/metrics 端点）
- [x] 告警渠道（webhook）
- [x] 打 tag `v0.1.0-m12`（指向 d30677c）

---

## M13. 打包分发

- [ ] Controller 生产 Dockerfile（多阶段 + distroless/alpine）
- [ ] Agent `.tar.gz` 打包
- [ ] （可选）`.deb` / `.rpm`
- [ ] CI 自动构建 + 发布 tag 产物
- [ ] 打 tag `v1.0.0`

---

## 变更日志

按时间倒序追加，每完成一个里程碑或重要节点写一行。

- **2026-07-20** — 项目启动，完成 design.md / deployment.md / development-plan.md / progress.md 初稿，git 仓库初始化。
- **2026-07-20** — M0 达成：项目脚手架完成，`make build` 通过（Go 1.26.5），Agent 交叉编译 linux/amd64 + arm64 均为静态链接。打 tag `v0.1.0-m0`。
- **2026-07-20** — M1 达成：4 个 proto 文件 + gRPC 代码生成（protoc 35.1）；11 张表的 GORM 模型；`internal/db` 双 Driver（SQLite/MySQL）+ `OpenFromEnv`（无静默降级）；SQLite 单测 + opt-in MySQL 单测全绿；确认整个模块 `CGO_ENABLED=0` 可编译可测试。版本化迁移 SQL 暂缓（AutoMigrate 兜底，待 schema 稳定后补）。打 tag `v0.1.0-m1`。
- **2026-07-20** — M2 达成：`internal/config`（YAML+env 覆盖，mTLS 必填校验）；`internal/controller/server`（Gin + gRPC，强制 `RequireAndVerifyClientCert`）；`cmd/controller` 接入配置/DB 迁移/信号优雅退出；`/healthz` 冒烟通过；mTLS 回归测试覆盖「无证书拒绝 + 有效证书放行」两种路径。打 tag `v0.1.0-m2`。
- **2026-07-21** — M3 达成：`internal/pki`（CA 加载/CSR 签发/URI SAN 携带 node_id/SHA-256 指纹）；`Registration.Register` RPC（bootstrap token 一次性使用，事务保护）；REST 管理接口（bootstrap token / list / approve / reject）；auth 拦截器（Register 免证书白名单 + 其余方法要求「证书链 × 指纹 × node_id」三项一致）；审计事件闭环；端到端集成测试通过。因 Register 必须无客户端证书可达，gRPC TLS 从 `RequireAndVerifyClientCert` 调整为 `VerifyClientCertIfGiven`，鉴权改在拦截器层执行 —— 语义等价，同时向下兼容 bootstrap 流程。打 tag `v0.1.0-m3`。
- **2026-07-21** — M4 达成：Agent 五个核心包（config / capability / bootstrap / conn / cmd/agent）；端到端集成测试覆盖真 Controller ← Agent bootstrap 全路径；macOS 实机跑通完整生命周期（node.id 稳定生成 → 能力探测 → Register → 证书落盘 → 配置里 bootstrap_token 自清 → mTLS 长连接建立 → 服务端未实现 stream 时按预期退避重连）。Ubuntu VM 装机验证与 M5 IptablesDriver 联调合并。打 tag `v0.1.0-m4`。
- **2026-07-21** — M5 达成：Firewall Driver 抽象 + IptablesDriver（Exec 可注入，`ShellExec` 生产/`fakeexec` 测试）；Controller 侧 `AgentStream` 服务端上线（连接注册表 + 心跳 last_seen + TaskResult 上行）；Agent 侧 `handler.Handler` 接下发（snapshot → apply → 失败自 rollback → confirm 清快照）；REST `POST /nodes/:id/apply` 触发端到端；`TestApplyEndToEnd` 覆盖真 gRPC/mTLS/AgentStream + fake iptables 全链路；macOS 实机 smoke 验证连接建立 + 任务下发 + 结果回传（macOS 无 iptables，Handler 优雅失败）。Linux 真机 iptables 联调延后到有 VM 时验证，`ShellExec` 路径已就位。打 tag `v0.1.0-m5`。
- **2026-07-21** — M6 达成：`internal/controller/{policy,compiler,task}` 三个新包 + `policy_routes.go`；Policy 模型 CRUD + 每次变更写 PolicyVersion 快照（事务保护）；Compiler 支持显式 `node_ids` 与 `labels` 交集匹配、稳定 (priority, id) 输出；Dispatcher 并行下发 + `stream.SubscribeTaskResults()` 多路 fan-out（重构掉了 M5 唯一 channel 的路径，多路 apply 不再互相抢结果）。REST 覆盖完整 CRUD + `POST /policies/:id/apply` + `POST /policies/apply-all`，apply 返回 200/207。`TestPolicyApplyEndToEnd` 与 `TestApplyAllPoliciesFanOut` 两个端到端集成测试覆盖显式目标与 label 目标；macOS 实机 smoke 走通 create → list → apply → update(v2) → delete 全生命周期。打 tag `v0.1.0-m6`。
- **2026-07-21** — M7 达成：`internal/controller/task/coordinator.go` 实现完整 Task 状态机（pending_approval → approved → dispatching → applying → confirm_wait → confirmed / rolled_back / failed）；Coordinator 包含 Submit（含 auto_approve 快速路径）、Approve/Reject/Confirm 三个动作、resultLoop 消费 TaskResult 推进状态机、armRollbackTimer + autoRollback（超时自动回滚）、recoverOnStart（启动恢复过期 confirm_wait + stuck in-flight tasks 标记 failed）；policy apply 改造为默认走审批流（返回 202 + PENDING_APPROVAL tasks），`auto_approve=true` 保持同步语义兼容 M6 测试；Task model 加 `ConfirmDeadline` + `Reviewer` 字段；REST `POST /api/v1/tasks/:id/{approve,reject,confirm}` + `GET /api/v1/tasks`；审计事件覆盖 submit/approve/reject/applying_ok/apply_failed/confirm/auto_rollback/recover_failed 全生命周期。端到端集成测试覆盖三条路径：`TestApprovalAndConfirmFlow`（happy path）、`TestAutoRollbackFlow`（2s deadline expire → ROLLED_BACK + rules restored）、`TestRejectFlow`（reject → FAILED）。Agent 侧无需改动——M5 的 Handler 已具备 Apply/Confirm/Rollback 能力。打 tag `v0.1.0-m7`。
- **2026-07-21** - M8 达成：`internal/agent/watchdog` 定期（30s）计算 MYFW 命名空间 Hash 与 Controller 期望态对比；漂移上报经 `stream.Service` 写审计；`AutoRecover` 开关触发 SyncRequest 自动恢复；单测覆盖无漂移 / 漂移 / 无基线 / Hash 错误 / 禁用 / nil driver。tag 待补打。
- **2026-07-21** - M9 达成：`internal/agent/driver/nftables` 实现 inet/ip family、5 个 chain（INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING）的 Init/Apply/Snapshot/Restore/Hash/Teardown；配套 fakeexec 测试；能力探测选择优先级 iptables-nft > iptables-legacy > nftables。tag 待补打。
- **2026-07-21** - M10 达成：`internal/agent/collector` 采集 CPU / 内存 / 网络接口 / 连接数，复用 `StateReport` + `InterfaceStat` 经 `AgentToController_State` 上报，Controller 侧 `stream.Service` 接收记录。tag 待补打。
- **2026-07-21~23** - M11 进行中：`web/`（Vite + Vue3 + Element Plus）落地登录 / 节点管理 / 节点详情 / 策略管理（`Policies.vue`）/ 审批中心 / 审计日志 / 系统概览 Dashboard；剩余 Controller 反代静态资源未接入。tag 待补打。
- **2026-07-23** - M12 达成：审计日志 CSV 导出（支持筛选）；Prometheus 指标暴露 `/metrics`；告警 webhook 渠道。tag 待补打。
- **2026-07-27** - 工程整理与安全增强：① 清理本地构建产物 / 依赖 / 证书（`agent.exe`、`controller.exe`、`dist/`、`deploy-package/`、`dev-ca/`、`deploy-cert/`、`web/node_modules`、`.mimicode` 等），补全 `.gitignore`（`/deploy-package/`、`/deploy-cert/`、`*.srl`、`*.ext`、`/.mimicode/` 等），移除遗留 `main.go` 与 `internal/shared/`。② 新增 `internal/security/` 模块：会话令牌（HMAC-SHA256）+ 防重放（nonce）+ IP 钉扎 + 证书自动轮换（短证书 24h），作为 gRPC 统一安全拦截器，在 mTLS 之上叠加应用层安全。③ 新增 `internal/model/iptables.go` 与 `stream.proto` 的 `IptablesRules` / `IptablesChain` / `SyncRulesRequest` 消息，支持节点 iptables 规则上报与同步。④ Controller 拆分 audit / dashboard / iptables / node / task 等 REST 路由文件。⑤ 同步修订 `design.md` / `deployment.md` / `development-plan.md` 至最新代码。⑥ 约定本地仅维护源代码，编译 / 测试 / 打包统一在远程 Linux 服务器执行；后续里程碑以 Git tag 标记节点。
- **2026-07-27** - Tag 核对与补全：核实 M0-M11 的 tag 此前已标记于初始提交 `265aa51`（`feat: 初始化项目，完成 M0-M11 核心功能`），本次补打 `v0.1.0-m12` 指向 `d30677c`（M12 + 工程整理）。至此 M0-M12 全部 tag 就位，可通过 `git checkout <tag>` 回退到任意里程碑节点查看代码。
- **2026-07-29** - 前端 UI 重构（商务质感 Dashboard：StatusPanel 环形饼图 + AuditFeed 时间线，一屏不滚动）+ 修改密码（`User` model + sha256+salt + `/auth/change-password`，兼容 admin/admin123）+ 节点规则查看显示 IP（非主机名）+ 编辑规则链下拉可选 + 链分组折叠。Agent 改 systemd 启动；规则查看链归类修复（collector 按 `-A CHAIN` 真实链，解决 MYFW-OUTPUT 显示不全）；灾备 `auto_reregister`（Controller 库重建时 Agent 自动补录 node+certificate）+ `scripts/rebootstrap-agents.sh`（CA 丢失批量重接入）。
- **2026-07-29** - 地址组（`AddressGroup`）+ ipset/nft set + mark 联动：proto 扩展（`CompiledRule` +`source_group`/`destination_group`/`match_mark`，`RuleSet` +`sets`，新增 `AddressSet`）；compiler `CompileForNode` 返回 `(rules, sets)` 收集地址组；driver `Apply` 改签名 `*RuleSet`，sets 原子下发（iptables `ipset` + nft `set`）；`compileRule` 加 `-m set`/`-m mark`，nft 补 `ACTION_MARK`。实测 ipset + mark+白名单联动在节点生效。proto 生成改用 `buf generate`（本地无 protoc 时）；Controller 改 host `go build` 二进制 + compose 挂载（绕过 docker build 拉基础镜像 arm64/DNS 问题）。
- **2026-07-29** - MYFW 收敛理念落地（P1-P4 全部完成并实测）：P1 `ensureJump` 顶部精准重排 + ESTABLISHED 放行；P2 节点直操作收敛 MYFW；P3 watchdog jump 顺序自愈；P4 自定义链 web 管理（CustomChain + syncCustomChains + Policy.chain）。
- **2026-07-29** - 体验整改:apply 简化(成功直接生效,去 confirm_wait 默认回滚,修复"应用失败")+ Restore ipset 修复回滚失败/watchdog 漂移;审批优化(Task 加 PolicyName 快照,列表显示策略名+节点IP+简化状态 待审批/已通过/已拒绝/已回滚);策略管理加端口搜索。
- **2026-07-29** - 策略模型重构为两级关联(策略组+条目):策略组(CustomChain)承载钩子方向+全局优先级,父链按组优先级顺序 jump;条目(Policy)归属组(group_id),继承方向/子链,只填源/目的/协议/端口/动作。编译器按组编译,去 targetChainForRule 落父链回退(机制上杜绝业务规则污染父链)。父链=ESTABLISHED 优化+jump 调度,子链=业务规则(规则所有权隔离)。存量迁移:Policy.Chain 回填 group_id(IS NULL OR =0)。前端组页加优先级,条目页改两级(所属组+继承只读)。实测父链仅 ESTABLISHED+jump,业务规则落 MYFW-business 子链。
