# 项目代码分析

> 文档自动生成于 2026-08-06。后续代码修改涉及结构变化（新增/删除文件、接口变更、model 字段变化）时需同步更新。

## 项目概述

**项目名**：iptables-tool（MYFW）
**模块名**：iptables-tool（Go module）
**描述**：防火墙规则管理系统，Controller（控制面）+ Agent（执行面）架构，通过 mTLS/gRPC 长连接管理远程 Linux 主机的 iptables/nftables 规则。

## 技术栈

| 层 | 技术 |
|------|------|
| 后端语言 | Go 1.26（CGO_ENABLED=0） |
| Web 框架 | Gin（HTTP）+ gRPC（双向流） |
| 数据库 | SQLite（dev）/ OceanBase MySQL（prod），GORM ORM |
| 协议 | Protobuf（buf 生成），mTLS 双向认证 |
| 前端 | Vue 3 + Element Plus + Vite |
| 部署 | Docker 多阶段构建（alpine 运行时） |
| CA/PKI | 自建 CA，Agent 客户端证书签发 |

## 目录结构

```
├── cmd/
│   ├── controller/         # Controller 入口（Web + gRPC 服务器）
│   └── agent/              # Agent 入口（systemd 服务，长连接 + 防火墙驱动）
├── internal/
│   ├── model/              # GORM 数据模型（19 个实体）
│   ├── agent/              # Agent 端逻辑
│   │   ├── bootstrap/      # 首次引导注册（token 交换证书）
│   │   ├── capability/     # 主机能力探测（iptables/nftables/docker/k8s）
│   │   ├── collector/      # iptables 规则采集器;v1.4 CollectRuleHits(iptables -L -v -n -x 解析 pkts/bytes + comment 反解实例 ID,规则活性分析)
│   │   ├── config/         # Agent 配置加载
│   │   ├── conn/           # mTLS 连接管理与长连接 Loop
│   │   ├── driver/         # 防火墙驱动抽象
│   │   │   ├── iptables/   # iptables 驱动实现
│   │   │   └── nftables/   # nftables 驱动实现
│   │   ├── handler/        # Controller 消息调度（Apply/Rollback/Renew/Decommission）
│   │   └── watchdog/       # 规则漂移检测
│   ├── controller/         # Controller 端逻辑
│   │   ├── revision/       # 规则库版本档案(计划三):ArchiveApply/Archive/List/Load,归档期望态 RuleSet,保留最近 30 份
│   │   ├── asset/          # 节点管理 REST API（bootstrap token 创建/审批/拒绝）
│   │   ├── audit/          # 审计日志
│   │   ├── auth/           # Web 会话认证
│   │   ├── compiler/       # 规则编译（策略 -> iptables 规则）
│   │   ├── policy/         # 策略服务
│   │   ├── registration/   # gRPC 注册服务（首次注册 + 证书续签）
│   │   ├── server/         # Gin 路由 + gRPC 服务器组装（15 个路由注册函数）
│   │   ├── simulator/      # 流量仿真预演引擎(计划二):纯函数 Evaluate(flow, rules, chains, sets) 输出命中路径 + 最终判定;首版 filter 表无状态匹配,支持地址组/MARK/优先级
│   │   ├── stream/         # gRPC 双向流连接管理（消息收发 + 心跳）
│   │   ├── templateio/     # 模板库导入导出（Bundle/Export/Import）
│   │   └── task/           # 任务协调器（Apply/Confirm/Rollback 状态机）
│   ├── config/             # Controller 配置
│   ├── db/                 # 数据库连接与迁移
│   ├── pki/                # CA 加载、证书签发、指纹计算
│   └── security/           # 安全拦截器（mTLS + 会话 + HMAC + IP 钉扎）
├── api/myfw/v1/            # 生成的 protobuf Go 代码
├── proto/myfw/v1/          # Protobuf 源文件（4 个 .proto）
├── web/src/                # Vue 3 前端
│   ├── api/index.js        # REST API 封装（axios）
│   ├── router/index.js     # 路由配置
│   ├── views/              # 12 个页面组件
│   ├── components/         # 4 个通用组件
│   ├── composables/        # 3 个 composable（图表/格式化/iptables 解析）
│   ├── stores/             # Pinia 状态管理
│   └── layout/             # 布局组件
├── configs/                # 配置文件
├── deploy/                 # Docker 部署
├── scripts/                # 部署脚本
└── vendor/                 # Go vendor 依赖
```

## 后端架构

### 1. 入口点

**cmd/controller/main.go**（90 行）
- 加载配置 → 打开 DB → 迁移 → `server.New()` → `srv.Run(ctx)`（启动 gRPC + HTTP）
- 响应 SIGINT/SIGTERM 优雅关闭

**cmd/agent/main.go**（459 行）
- 加载配置 → 创建节点身份 → 能力探测 → 首次引导注册(bootstrap) → 证书轮换 → 防火墙驱动初始化 → 长连接 Loop
- `selfDestruct()`：删除节点时自毁逻辑（停 systemd + 删文件 + 退出），见第 334 行

### 2. 数据模型（internal/model/）

19 个实体，AutoMigrate 顺序由 `AllModels()`（models.go:11）定义：

| 实体 | 文件 | 行号 | 关键字段 |
|------|------|------|----------|
| Node | node.go:22 | `ID, Status, Hostname, Name, IP, MachineID, Labels, LastSeen, CreatedAt, DriftCount, CertNotAfter` |
| NodeCapability | node.go:47 | `NodeID, Distro, KernelVersion, IptablesVersion, SelectedBackend, BackendAvailable, BackendReason` |
| Certificate | node.go:65 | `NodeID, Fingerprint, NotAfter, Revoked` |
| BootstrapToken | node.go:79 | `Token, Note, ExpiresAt, UsedAt` |
| Policy | policy.go:7 | 策略规则（Source, Destination, Protocol, PortRange, Action, Targets等） |
| PolicyVersion | policy.go:35 | 策略版本快照 |
| Rule | policy.go:47 | 已编译的规则（iptables 格式） |
| PolicyTemplate | policy_template.go:7 | 策略模板（Policy 迁移后的产物）;v1.2 加 SpecVersion(规则字段单调版本,drift 判据,改描述不递增) |
| NodePolicyInstance | policy_template.go:33 | 节点策略实例（模板下发到具体节点）;v1.2 加 SyncedSpecVersion(同步时模板 spec 快照) |
| CustomChain | custom_chain.go:7 | 自定义子链(策略组);v1.3 加 Mounts(JSON []ChainMount 权威挂载列表)+ ChainMount 类型 + MountList()(空回退 Parent/Priority 单挂载,多钩子 P1b) |
| Task | task.go:21 | 任务（Apply/Confirm/Rollback）;v1.2 加 AutoConfirm 字段(自愈任务 apply 成功即确认,跳过保护期) |
| Approval | task.go:44 | 审批记录 |
| Snapshot | task.go:55 | 规则快照（Rollback 用） |
| AuditLog | task.go:67 | 审计日志 |
| IptablesRule | iptables.go:6 | 节点上报的 iptables 规则 |
| AddressGroup | address_group.go:8 | 地址组 |
| CustomChain | custom_chain.go:7 | 自定义链 |
| Mark | mark.go:8 | 防火墙标记 |
| User | user.go:7 | 用户 |
| SystemSetting | system_setting.go:7 | 系统设置(含一次性种子标记 seed.custom_chains.v1) |
| NodeRuleRevision | node_rule_revision.go:9 | 节点规则库版本档案(计划三):RevNo 节点内递增、Payload=期望态 RuleSet(protojson)、Source(apply/manual/rollback)、按保留策略最近 30 份清理 |
| RuleHitStat | rule_hit.go:9 | 规则命中统计(计划一):按 (node_id,instance_id) 唯一 upsert;Packets/Bytes 取同实例多条规则 max;死规则=enabled+有统计+packets=0+created_at 超 7 天 |

**预置常用链**（internal/model/seed.go）：`builtinCustomChains` 5 条(business-input/acl-forward/
mark-mangle/nat-prerouting/nat-postrouting)。`SeedCustomChains` 由 db.Migrate(db.go:164) 调用:
首次启动按 name 幂等播种,全部成功后写 SystemSetting `seed.custom_chains.v1=done`;
之后启动查标记已 done 直接跳过 → 用户删除/编辑后重启不重建不覆盖(seed_test.go 4 用例)。
版本化 key:清单变更改 v2 即增量播种。

### 3. Controller 模块

**Server 组装**（internal/controller/server/server.go）
- `Server` 结构体（第 42 行）：持有 cfg, db, ca, stream, policy, comp, co, sec, http, grpc
- `New()`（第 57 行）：构建所有依赖并组装 gRPC + HTTP 服务器
- `newWebHandler()`（第 328 行）：注册 12 组 Gin 路由 + 静态文件服务
- `Run()`（第 390 行）：启动 gRPC + HTTP 双服务器

**Gin 路由注册函数**（12 个，均在 internal/controller/server/）：

| 函数 | 文件 | 行号 | 功能 |
|------|------|------|------|
| registerNodeRoutes | node_routes.go:15 | 节点 CRUD（GET list/get/put/delete）+ 续签证书 |
| registerTaskRoutes | task_routes.go:18 | 任务列表/详情 |
| registerTaskLifecycleRoutes | task_lifecycle_routes.go:16 | 任务审批/确认/回滚 |
| registerPolicyRoutes | policy_routes.go:24 | 策略 CRUD + 编译 + 下发 |
| registerTemplateRoutes | template_routes.go:20 | 策略模板 CRUD + 导入导出 + checkMarkExists(MARK 值须存在于标记管理)+ 配置漂移治理(sync-preview 字段级 diff 预览 / sync-all 批量同步 / instanceDiffFields 偏离检测);v1.3 chain_unavailable 标记(P2 组生命周期显式化)+ chainTableFor(组链表 table,表一致性);v1.5 POST /templates 忽略前端 id(主键冲突修复)+ requireMarkSource(实例 MARK 源必填,模板可无源骨架)+ 实例化合并 body.source 覆盖 |
| registerAuditRoutes | audit_routes.go:15 | 审计日志查询/导出/dashboard/置信度 |
| registerDashboardRoutes | dashboard_routes.go:12 | 仪表盘统计 + config-drift(配置漂移统计:模板已更新但实例未跟的实例数) |
| registerIptablesRoutes | iptables_routes.go:20 | 节点 iptables 规则实时拉取/漂移检查;v1.4 规则活性分析(计划一):POST /iptables/hits/:node_id(Agent 上报命中率,同实例 max 聚合 upsert RuleHitStat)+ GET /iptables/rule-hits/:node_id(命中率列表+死规则判定,dead=enabled+有统计+packets=0+超 7 天) |
| registerAddressGroupRoutes | address_group_routes.go:19 | 地址组 CRUD |
| registerCustomChainRoutes | custom_chain_routes.go:18 | 自定义链 CRUD;v1.3 多挂载(mounts 权威+Parent/Priority 镜像回退,返回 mount_list)+ 禁用链审计 chain.disabled(含 affected_instances) |
| registerMarkRoutes | mark_routes.go:18 | 标记 CRUD |
| registerSystemRoutes | system_routes.go:16 | 系统设置（保留策略/清理） |
| registerRevisionRoutes | revision_routes.go:18 | 规则库版本档案(计划三):GET /nodes/:id/revisions 历史列表 + POST /revisions/:no/rollback 回滚(先归档当前版本再下发历史 RuleSet,走保护期) |
| registerSimulateRoutes | simulate_routes.go:12 | 流量仿真预演(计划二):POST /api/v1/simulate,入参 node_id + flow 五元组(收敛到节点级:基于该节点 CompileForNode 编译的 CompiledRule 推演,不接受外部规则集内联),返回 verdict/steps/note |

**节点管理 REST API**（internal/controller/asset/asset.go）：
- `POST /api/v1/nodes/bootstrap` — 创建 bootstrap token（第 64 行）
- `GET /api/v1/nodes` — 节点列表（支持 status 过滤，第 90 行）
- `POST /api/v1/nodes/:id/approve` — 审批通过（第 104 行）
- `POST /api/v1/nodes/:id/reject` — 拒绝（第 108 行）

**gRPC 注册服务**（internal/controller/registration/registration.go）：
- `Register()`（第 55 行）：首次注册（bootstrap token 交换证书）或续签（空 token 走 renewCert 分支）
- `renewCert()`（第 194 行）：吊销旧证书 + 签发新证书
- 注册时 Node.Name 写入 token.Note（第 120 行）

**gRPC 流服务**（internal/controller/stream/stream.go）：
- `Service` 结构体（第 36 行）：持有 DB, Registry, 订阅者
- `Connect()`（第 109 行）：Agent 长连接接入点，处理全双工流
- `SendDecommission()`（第 473 行）：删除节点时下发注销指令
- `SendRenewCert()`（第 457 行）：续签指令
- `SendRuleOperation()`（第 403 行）：增删改插规则
- `RequestRulesAndWait()`（第 377 行）：拉取节点实时规则
- `auditDrift()`（第 504 行）：收到 Agent drift 上报时同步写 `node.drift` 审计 + 异步分类
- `classifyAndAudit()`：异步编译 expected(`CompileExpected` 注入) + 拉 actual + `classifyDrift` 分类,补写 `node.drift.classified` 审计(区分篡改/删除/重启丢失)
- `Registry`（第 548 行）：在线节点连接注册表
  - `Register()`（第 571 行）：注册连接
  - `Deregister()`（第 581 行）：注销连接
  - `Send()`（第 600 行）：向指定节点发送消息

**gRPC 认证拦截器**（internal/controller/server/server.go）：
- `checkAuth()`（第 211 行）：业务层认证（证书吊销检查、节点状态、autoReregister）
- `autoReregister()`（第 272 行）：Controller 数据库重建后自动注册存量 Agent

**策略/模板**（internal/controller/policy/ + compiler/ + rulespec/）：
- `policy.Service`：策略 CRUD
- `compiler.Compiler`：策略编译为 iptables 规则;v1.2 MARK 白名单实例不消费组链(compileInstances 预加载组跳过 isMarkACL 的 GroupID,组不存在不整条失效);v1.3 组即落点(compileInstances 用 GroupID 查链),loadCustomChains 按链×挂载展开同名多条 CustomChainDef(多钩子,零 proto),compileInstance 传 chainTable 做 DNAT/SNAT 表一致性校验
- `rulespec.Spec.Validate`：规则字段唯一校验权威(API 入口/编译器/Agent driver 三层复用,无 DB);v1.2 MARK 打标值非零即合法(不再硬编码 15/255),引用完整性(标记必须存在于 Mark 表)由 API 层 `checkMarkExists` 承担;v1.3 加 ChainTable 字段,DNAT/SNAT 须 nat 表链(动作-链表一致性);v1.5 MARK 源校验移除(模板可无源骨架,源校验移至实例层 requireMarkSource)
- 配置侧漂移治理(template_routes.go)：`instanceDrift`(模板 SpecVersion 判据)+ `instanceDiffFields`/`instanceDeviated`(实例参数 vs 模板当前参数,不依赖 SpecVersion)+ `applyTemplateToInstance`(sync 单条与 sync-all 批量共用的全量覆盖)+ `instFieldLabel/instFieldValue/tplFieldValue`(diff 预览中文字段名);`GET /instances/:id` 返回 drift_fields/deviated/deviated_fields;v1.3 `chain_unavailable` 标记(P2 组生命周期显式化)+ `chainTableFor`(组链表 table,表一致性)

**流量仿真预演**（internal/controller/simulator/,计划二）：
- `simulator.Flow`(direction/source_ip/dest_ip/protocol/src_port/dst_port/mark,均带 JSON tag)
- `simulator.Evaluate(flow, rules, chains, sets) *Result`：纯函数无副作用。语义对齐 driver.Apply——所有规则落子链 MYFW-<chain>,父链 MYFW-INPUT/FORWARD/OUTPUT 仅 conntrack+子链 jump;INPUT/FORWARD 先 mangle 打标预遍(挂 MYFW-MANGLE 的 mangle 链仅 MARK 生效,支撑 MARK 白名单主场景),再按链定义顺序(compiler priority 升序)进各 filter 子链,链内按 priority 升序、次按 id 线性匹配;ACCEPT/DROP/REJECT 终止,MARK 打标继续(后续 match_mark 命中),DNAT/SNAT 提示不支持继续;无命中返回 PASS(默认策略放行)
- 支持源/目的 IP/CIDR、地址组(set 成员 ipset 语义)、协议、端口区间("22"/"1000-2000")、match_mark;首版无状态匹配,仅 filter 终止判定 + mangle 打标,其余表/动作跳过;tcp/udp 流未指定 dst_port 不命中带端口规则
- `Result{verdict, steps[], note}`：steps 记录逐条规则匹配结果(chain/rule_id/action/mark/matched/note)

**任务协调器**（internal/controller/task/coordinator.go）：
- `Coordinator`：Apply → 审批 → 确认/回滚 状态机
- `SubmitOpts`：Author/AutoApprove/AutoConfirm(自愈跳过保护期)/Scene(审计场景)
- 计划三回滚链路：Task 加 `RuleSetSnapshot`(protojson RuleSet,回滚任务专用)；`SubmitRuleSet`(给定规则集建回滚任务,dispatch 时快照非空跳过编译直接用历史规则集)；handleResult 回滚任务成功后实例 applied 全置 false(规则已偏离当前定义)；`ArchiveFn` 回调普通任务 Apply 成功归档(revision.Service 注入)
- `HasInFlight(nodeID)`：OnSync 去重(节点有 pending_approval/dispatching/applying/confirm_wait 任务时跳过)
- `SubmitRemoval(instanceID,opts)`：移除实例保护期任务,事务内原子创建 task+标记 pending_delete 并关联 task_id(漏洞 G 修复)
- `refreshNodePreview`：审批 dispatch 时用最新实例刷新 diff 预览,排除 pending_delete(漏洞 F' 修复)
- `handleResult`：AutoConfirm 任务 apply 成功直接 confirmed(发 Confirm 释放 Agent 快照,审计 scene=self_heal);失败仅回退 enabled 实例 applied、成功不动 pending_delete 实例(漏洞 J/S 修复)

**安全层**（internal/security/）：
- `SecureInterceptor`：gRPC 拦截器（mTLS + 会话令牌 + HMAC 签名 + IP 钉扎 + 防重放）
- `CertRotation`：证书轮换（24h TTL，5h 前续签）

**CA/PKI**（internal/pki/pki.go）：
- `CA` 结构体（第 24 行）：加载 CA 证书+密钥
- `SignAgentCert()`（第 46 行）：签发 Agent 客户端证书（CN=nodeID, URI SAN=myfw:node:<id>）
- `Fingerprint()`（第 84 行）：计算证书指纹（SHA-256）
- `NodeIDFromCert()`（第 105 行）：从证书提取节点 ID

### 4. Agent 模块

**连接管理**（internal/agent/conn/conn.go）：
- `TLSMaterial`（第 38 行）：TLS 配置材料
- `Dial()`（第 49 行）：构建 mTLS 连接
- `Handler` 接口（第 132 行）：
  - `OnApply()` — 规则下发
  - `OnConfirm()` — 确认
  - `OnRollback()` — 回滚
  - `OnSyncRules()` — 同步规则
  - `OnRuleOperation()` — 规则操作（增删改插）
  - `OnExec()` — 专家模式命令
  - `OnRenewCert()` — 续签证书
  - `OnDecommission()` — 注销自毁
- `NopHandler`（第 215 行）：空实现
- `ErrSelfDestruct`（第 240 行）：自毁信号
- `ShouldSelfDestruct()`：判断是否需要自毁（Unauthenticated/PermissionDenied 触发）

**消息处理器**（internal/agent/handler/handler.go）：
- `Handler` 结构体（第 34 行）：持有 Driver + 各种回调函数（RulesCollector, RuleExecutor, ExecExecutor, RenewCertFn, DecommissionFn）
- `OnDecommission()`（第 86 行）：调用 DecommissionFn 自毁
- `OnApply()`（第 103 行）：备份快照 → 执行规则 → 通知 watchdog

**防火墙驱动**（internal/agent/driver/）：
- `driver.Driver` 接口：`Apply()`, `Snapshot()`, `Restore()`
- `iptables.Driver`：`iptables-restore` 方式应用规则集;v1.4 compileRule 追加 `-m comment --comment "myfw:<规则Id>"`(编码实例 ID,供 Agent 命中率采集反解)
- `nftables.Driver`：`nft -f` 方式应用规则集

**引导注册**（internal/agent/bootstrap/）：
- `Do()`：bootstrap token 发送到 Controller → 获取客户端证书 → 持久化

**能力探测**（internal/agent/capability/）：
- `Detect()`：探测主机发行版、iptables/nftables 版本、Docker/K8s

**规则漂移检测**（internal/agent/watchdog/）：
- `Watchdog`：定时检查当前规则 hash 是否匹配期望值，漂移则上报

### 5. Protobuf 协议（proto/myfw/v1/）

| 文件 | 定义 |
|------|------|
| common.proto | 枚举（Direction, Protocol, Action, FirewallBackend）+ Capability, MachineFingerprint, Timestamp |
| registration.proto | `Registration` 服务（Register RPC）+ RegisterRequest/Response, RenewCertRequest/Response |
| stream.proto | `AgentStream` 服务（Connect 双向流 RPC）+ 消息类型（Heartbeat, ApplyTask, TaskResult, DriftReport, IptablesRules, RuleOperation, ExecCommand, RenewCertCommand, DecommissionCommand 等） |
| rule.proto | CompiledRule, RuleSet, AddressSet, CustomChainDef |

## 前端架构

### 页面路由（web/src/router/index.js）

| 路径 | 组件 | 功能 |
|------|------|------|
| /login | Login.vue | 登录 |
| /dashboard | Dashboard.vue | 仪表盘 |
| /nodes | Nodes.vue | 节点管理（列表/添加/编辑/删除/审批/规则查看） |
| /policies | NodePolicies.vue | 策略管理 |
| /templates | TemplateLibrary.vue | 策略模板库 |
| /node-policies | NodePolicies.vue | 节点策略实例(含单条策略预演抽屉:预期目标 vs 实际模拟通道流程图,五元组仿真命中路径,计划二) |
| /address-groups | AddressGroups.vue | 地址组 |
| /custom-chains | CustomChains.vue | 自定义链 |
| /approve | Approve.vue | 审批任务 |
| /audit | Audit.vue | 审计日志 |
| /settings | SystemSettings.vue | 系统设置 |

### API 封装（web/src/api/index.js）
- 基于 axios，baseURL 自动适配
- 38 个导出函数，覆盖所有 REST API(含计划三 revisions/rollback + 计划二 simulateFlow)

### 组件
- `AuditFeed.vue` — 审计实时推送
- `ConfirmGuard.vue` — 保护期确认弹窗
- `StatCard.vue` — 统计卡片
- `StatusPanel.vue` — 状态面板

## 关键文件速查

| 文件 | 行数 | 核心职责 |
|------|------|----------|
| cmd/controller/main.go | 90 | Controller 入口 |
| cmd/agent/main.go | 459 | Agent 入口 + selfDestruct |
| internal/controller/server/server.go | 446 | 服务器组装 + 路由注册 + gRPC 拦截器 |
| internal/controller/server/node_routes.go | 179 | 节点 CRUD REST API |
| internal/controller/stream/stream.go | ~660 | gRPC 双向流 + 心跳 + 消息转发 + drift 异步分类 |
| internal/controller/stream/drift_classify.go | ~170 | 运行时 drift 来源分类纯函数(external_tamper/rule_removed/restart_loss/unspecified) |
| internal/controller/templateio/templateio.go | ~180 | 模板库导入导出（Bundle/Export/Import） |
| internal/controller/registration/registration.go | 381 | 首次注册 + 证书续签 |
| internal/controller/asset/asset.go | 167 | 节点管理 REST（token/审批/拒绝） |
| internal/agent/conn/conn.go | ~250 | mTLS 连接 + Handler 接口 + Loop |
| internal/agent/handler/handler.go | ~260 | 消息分发（Apply/Rollback/Exec/Decommission） |
| internal/agent/bootstrap/bootstrap.go | — | 首次引导注册 |
| internal/model/node.go | 86 | 节点 + 证书 + 能力探测模型 |
| internal/model/policy.go | — | 策略模型 |
| internal/model/policy_template.go | — | 策略模板 + 节点实例模型 |
| internal/model/task.go | — | 任务 + 审批 + 快照 + 审计日志模型 |
| internal/pki/pki.go | 168 | CA 管理 + 证书签发 + 指纹计算 |
| internal/security/interceptor.go | — | gRPC 安全拦截器 |
| internal/security/rotation.go | — | 证书轮换 |
| proto/myfw/v1/stream.proto | ~200 | 双向流协议定义 |
| web/src/views/Nodes.vue | ~983 | 节点管理页面 |
| web/src/views/Dashboard.vue | — | 仪表盘 |
| web/src/api/index.js | — | 前端 API 封装 |