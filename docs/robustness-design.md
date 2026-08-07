# 健壮性设计：四支柱方案

> 目标：从架构层面永久消除"校验放行但执行失败""状态展示与实际不符""错误被吞""资源残留"四类问题。
> 创建：2026-08-07。

## 一、问题根因归类

当前所有故障归结为 4 个架构缺陷，每个缺陷对应多个表面 bug：

| 缺陷 | 表面问题 | 根因 |
|------|----------|------|
| 校验/编译/执行三层语义不一致 | ANY+端口下发失败、MARK 无 mark 值 | 三层各自实现校验，约束不同步 |
| 状态多源，展示≠实际 | 假在线（status=ACTIVE 但断连）、假已下发（乐观标记） | Node.Status(审批)/Registry(连接)/Applied(下发) 各自维护 |
| 错误链路断裂，下发前不预检 | Submit 吞错误、规则无效要等 Agent 才发现 | 下发前不编译预检，错误不透传 |
| 资源生命周期不完整 | 幽灵证书（5条）、旧版 Agent 残留 | 删节点不级联清理证书 |

## 二、四支柱设计

### 支柱1：规则校验单一真相源

**原则**：规则的合法性只有一份校验逻辑，API 入口、编译器、Agent driver 三层复用，约束与 iptables/nftables 实际能力对齐。

**实现**：
- 新建 `internal/controller/rulespec` 包，定义 `Spec`（规则字段子集）+ `Validate()` 方法。
- `Validate()` 覆盖与底层一致的约束：
  - `port_range` 非空 -> `protocol` 必须是 TCP/UDP（ANY/空/ICMP 均拒绝）
  - `protocol=ICMP` -> 不允许 `port_range`
  - `action=MARK` -> `mark` 必须是 15/255
  - `action=DNAT/SNAT` -> `nat_to` 必填
  - `action=MARK` + 源地址/地址组 -> `port_range` 必填（白名单拦截完整性）
- `policy.ValidateFields` 改为委托 `rulespec.Validate`，消除重复逻辑。
- `compiler.compileInstance` 编译前调用 `rulespec.Validate`，防旧脏数据绕过。
- Agent driver 收到规则后保留防御性校验（最终防线，已有）。

**效果**：规则要么在入口被拒，要么一定能执行；永不出现"落库成功但 Agent 拒绝"。

### 支柱2：状态单一真相源

**原则**：每个状态字段只有一个权威来源，前端展示从权威来源派生，不存冗余/乐观状态。

| 状态 | 唯一来源 | 说明 |
|------|----------|------|
| 节点在线 | `Registry.Connected()` | gRPC 实时连接，不是审批状态 |
| 节点审批 | `Node.Status` | PENDING/ACTIVE/ARCHIVED，语义改为"审批状态" |
| 实例已下发 | `TaskResult` 驱动 | `Applied` 由 `handleResult` 更新（已修复） |

**实现**：
- `node_routes.go` 节点列表 API：调用 `streamSvc.Reg.Connected()`，为每个节点附加 `online bool` 字段。
- 前端节点列表"在线"列改用 `online`，不再用 `status` 推断。
- 下发前连接预检：`dispatch` 路由在 `Submit` 前检查节点是否在 `Registry`，无连接直接返回 409 + 明确错误，不创建 task。

**效果**：前端显示的在线/已下发就是真实状态，永不"假在线""假已下发"。

### 支柱3：Fail-Fast 下发链路

**原则**：错误在最早阶段拦截。下发前预编译，规则无效/节点离线立即返回，不创建无意义 task。

**实现**：
- `coordinator.Submit` 在创建 task 前，对每个目标节点调用 `CompileForNode` 预编译：
  - 编译失败（含 rulespec 校验失败）-> 直接返回错误，不创建 task。
  - 节点未连接 -> 直接返回错误（支柱2 的连接预检）。
- `Submit` 错误全链路透传（已修复：`approveAndDispatch` 错误返回调用方）。
- `dispatch` 路由返回 task 列表 + 任何编译/连接错误，前端展示。
- 前端下发按钮：调用后根据返回的 task 状态/错误展示结果，不再乐观假设成功。

**效果**：下发失败用户立即看到原因（规则无效/节点离线），无需翻 task 列表排障。

### 支柱4：资源生命周期完整性

**原则**：创建与删除对称，删除主资源时事务级联清理所有关联资源，不留孤儿。

**实现**：
- `node_routes.go` DELETE 节点：一个事务内删除 `Node` + `Certificate`(全部) + `NodePolicyInstance`(全部) + 关联 `Task`。当前只标记证书 revoked + 删 Node，遗留实例和 revoked 记录。
- `coordinator.recoverOnStart` 启动恢复时增加一步：物理删除 `node_id` 不在 `nodes` 表的 `certificates` 记录（幽灵证书清理）。
- Agent 版本契约（长期）：Agent 上报版本，Controller 记录到 `nodes.agent_version`，不兼容版本前端提示升级。本次先加字段+上报，不强制拒绝。

**效果**：删节点即彻底清理，无幽灵数据；Agent 版本可追溯。

## 三、实施清单（文件级）

| 阶段 | 文件 | 改动 |
|------|------|------|
| 1 规则校验统一 | `internal/controller/rulespec/rulespec.go`（新） | `Spec` + `Validate()` |
| 1 | `internal/controller/rulespec/rulespec_test.go`（新） | 覆盖正常/边界/异常 |
| 1 | `internal/controller/policy/policy.go` | `ValidateFields` 委托 rulespec |
| 1 | `internal/controller/compiler/compiler.go` | `compileInstance` 前置 rulespec 校验 |
| 1 | `internal/agent/driver/iptables/iptables.go` | 对齐 PROTOCOL_ANY 处理（防御） |
| 2 在线状态收口 | `internal/controller/server/node_routes.go` | 节点列表附 `online` 字段 |
| 2 | `internal/controller/server/template_routes.go` | dispatch 前连接预检 |
| 2 | `web/src/views/Nodes.vue` | 在线列改用 `online` |
| 3 Fail-Fast 下发 | `internal/controller/task/coordinator.go` | `Submit` 前编译预检 |
| 3 | `internal/controller/server/template_routes.go` | dispatch 返回错误详情 |
| 3 | `web/src/views/NodePolicies.vue` | 下发结果展示 |
| 4 资源清理 | `internal/controller/server/node_routes.go` | DELETE 级联清理 |
| 4 | `internal/controller/task/coordinator.go` | `recoverOnStart` 清幽灵证书 |
| 4 | `internal/model/node.go` | 加 `AgentVersion` 字段（长期） |
| 4 | 数据修复 SQL | 现有实例 protocol ANY->TCP、删幽灵证书 |

## 四、阶段划分

每阶段独立可验证，按依赖顺序推进：

1. **阶段1（规则校验统一）**：解决"所有节点下发失败"的根因。TDD：rulespec 测试先行。
2. **阶段2（在线状态收口）**：解决"假在线"。前端+后端联动。
3. **阶段3（Fail-Fast 下发）**：解决"错误被吞、排障困难"。依赖阶段1的编译校验。
4. **阶段4（资源清理）**：解决"幽灵数据"。独立，可最后做。

## 五、测试策略

- rulespec：表驱动测试，覆盖所有约束组合（ANY+端口、ICMP+端口、MARK 无 mark 等）。
- coordinator：Submit 预编译失败不创建 task。
- node_routes：节点列表 online 字段真实反映 Registry。
- 前端：在线列、下发结果展示。
- 远程验证：248/249 端到端下发成功 + 删节点无残留。


---

## 阶段5：移除链路与下发状态同步（2026-08-06 新增）

### 问题根因

1. **移除实例不删节点规则**：`DELETE /api/v1/instances/:id` 直接物理删 DB，不触发 dispatch。
   节点上 iptables 规则残留成孤儿。前端 `handleDeleteInst` 也只调删除接口，提示"需重新下发"
   但实例已从列表消失，用户不会再点下发。对比 `toggleEnabled`（改 enabled 后自动 dispatch），
   DELETE 链路缺了"触发移除下发"这一环。
2. **下发后状态不刷新**：`handleDispatch` 在 `await dispatchNode()` 后立即 `loadInstances()`。
   后端 dispatch 异步（Send 后返回 APPLYING），Agent 尚未回 TaskResult，`applied` 仍 false，
   前端显示"未下发"。Agent 几秒后成功，applied 变 true，前端无二次刷新。

### 方案

#### 5.1 移除链路重构（进保护期，可回滚）

移除即"禁用 + 下发移除 + 进保护期"，用户可在保护期面板 Confirm（确认删记录）或 Rollback（误删恢复规则）。

数据模型：`NodePolicyInstance` 加两个字段：
- `PendingDelete bool`：标记待删除。
- `PendingDeleteTaskID string`：关联的移除 task_id，Confirm 时清理、Rollback 时恢复（精确关联，避免同节点多 task 误伤）。

`DELETE /api/v1/instances/:id` 逻辑：
- `applied=false`（节点无规则）：直接删 DB，返回 204。
- `applied=true`（节点有规则）：
  1. 连接预检：节点未连接 -> 409「节点未连接，无法移除」。
  2. 置 `enabled=false, pending_delete=true`（保留 applied=true，供 Submit 识别"待禁用"生成 -D 移除）。
  3. `co.Submit(0, [nodeID], AutoApprove)` 触发移除下发，拿到 task_id。
  4. 置 `pending_delete_task_id = task_id`（关联本次移除）。
  5. 返回 202 + `{task_id, message:"已进入保护期，可回滚"}`。
  6. 若 Submit 失败：回滚标记（enabled=true, pending_delete=false），返回错误。

`coordinator.handleResult` 成功分支：已有 `Update("applied", gorm.Expr("enabled"))` 将 enabled=false
实例的 applied 置 false（规则已从节点移除）。**不自动删 DB**，等用户 Confirm。

`coordinator.Confirm`（用户确认移除）：成功后物理删除 `pending_delete=true AND pending_delete_task_id=task_id` 的实例。

`coordinator.Rollback`（误删回滚）：Agent 恢复快照（规则回来）后，恢复 `pending_delete=true AND pending_delete_task_id=task_id`
的实例：`enabled=true, pending_delete=false, applied=true, pending_delete_task_id=''`。

#### 5.2 下发状态同步（前端轮询 task 终态再刷新）

封装 `awaitDispatchResult(dispatchCall)`：
1. 执行 dispatchCall，取返回 `tasks[0].id`。
2. 每 1s 轮询 `getTask(task_id)`，状态 ∈ {confirm_wait, confirmed, failed, rolled_back} 停止。
3. 超时 15s 停止，提示「下发超时，请稍后查看」。
4. 终态后 `loadInstances()` + `guard.refresh()`，按状态提示成功/失败。

`handleDispatch`、`toggleEnabled`、`handleDeleteInst`（202 分支）均复用此封装。

### 涉及文件

| 改动 | 文件 | 说明 |
|---|---|---|
| 模型 | `internal/model/policy_template.go` | 加 `PendingDelete` 字段 |
| 后端 | `internal/controller/server/template_routes.go` | DELETE 重构 + 连接预检 |
| 后端 | `internal/controller/task/coordinator.go` | handleResult 清理 pending_delete |
| 前端 | `web/src/views/NodePolicies.vue` | 三 handler 改造 + 轮询封装 |
| 前端 | `web/src/api/index.js` | deleteInstance 透传 202 响应 |

### 测试

- 后端：DELETE applied=false 直接删；applied=true 未连接返回 409；applied=true 已连接置 pending_delete + dispatch；
  handleResult 成功后清理 pending_delete 实例。
- 前端：手动验证移除已下发实例 -> 节点规则消失 + 记录消失；下发后状态自动变"已下发"。
