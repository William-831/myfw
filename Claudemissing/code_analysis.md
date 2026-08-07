# 项目代码结构分析（go-iptablesops）

更新时间：2026-08-07。Go + Gin + gRPC + Vue3 + Element Plus。iptables 策略管理平台（Controller 管理端 + Agent 节点执行）。

## 核心链路：策略创建 → 下发 → 节点生效

```
前端 NodePolicies.vue / TemplateLibrary.vue
  → POST /api/v1/nodes/:id/instances (template_routes.go)
  → policy.ValidateFields (policy.go:264, 委托 rulespec.Validate)
  → 存库 NodePolicyInstance
  → POST /api/v1/nodes/:id/dispatch (template_routes.go:433)
  → task.Coordinator.Submit/approveAndDispatch (coordinator.go)
  → compiler.CompileForNode (compiler.go:34, 编译 NodePolicyInstance → CompiledRule)
  → gRPC ApplyTask → Agent handler → iptables/nftables driver
```

## 关键文件职责

### Controller 侧
| 文件 | 职责 | 核心符号 |
|------|------|---------|
| `internal/controller/rulespec/rulespec.go` | **校验单一真相源**，约束与 iptables 能力对齐 | `Spec.Validate()`(:32)、`IsMarkWhitelist()`(:87) |
| `internal/controller/policy/policy.go` | Policy(M6 旧模型) CRUD + 版本 + 校验 | `Service.Create/Update`、`ValidateFields`(:264) |
| `internal/controller/compiler/compiler.go` | 实例 → CompiledRule(可多条) | `CompileForNode`(:34)、`compileInstances`(:78)、`compileInstance`(:314)、`TargetNodes`(:209) |
| `internal/controller/server/template_routes.go` | 模板库 + 节点实例 CRUD + dispatch 路由 | `registerTemplateRoutes`(:23)、POST/PUT instances、`/dispatch`(:433) |
| `internal/controller/server/custom_chain_routes.go` | 策略组(自定义子链) CRUD + 引用检查 | `registerCustomChainRoutes` |
| `internal/controller/server/address_group_routes.go` | 地址组 CRUD + IP/CIDR 校验规范化 | `normalizeMembers`(:200) 裸 IP 补 /32 |
| `internal/controller/server/mark_routes.go` | 标记定义 CRUD | `registerMarkRoutes` |
| `internal/controller/task/coordinator.go` | 任务状态机(审批/保护期/回滚) | `Submit`(:124)、`approveAndDispatch`(:327)、`handleResult`(:402)、`fillNodeDispatchPreviewBatch`(:684) |
| `internal/controller/server/node_routes.go` | 节点管理 + 在线状态 | - |
| `internal/controller/stream/stream.go` | gRPC 双向流 + 连接注册 | `Service.Reg.Connected/Send` |

### 模型（internal/model）
| 文件 | 内容 |
|------|------|
| `policy_template.go` | `PolicyTemplate`(规则骨架) + `NodePolicyInstance`(节点实例快照,含 Applied/PendingDelete/PendingDeleteTaskID/SyncedTemplateUpdatedAt) |
| `policy.go` | `Policy`(M6 抽象规则,含 Targets JSON) + `PolicyVersion` + `Rule` |
| `models.go` | 迁移:Policy → PolicyTemplate + NodePolicyInstance |

### Agent 侧
| 文件 | 职责 |
|------|------|
| `internal/agent/driver/iptables/iptables.go` | iptables 驱动：Init/Apply/Snapshot/Restore；ipset 名 `MYFW-<name>`(:218,560)；custom chain `MYFW-<name>` |
| `internal/agent/driver/nftables/nftables.go` | nftables 驱动 |
| `internal/agent/handler/handler.go` | gRPC 消息处理 |
| `internal/agent/conn/conn.go` | mTLS 连接 |

### 前端（web/src/views）
| 文件 | 职责 |
|------|------|
| `NodePolicies.vue` | 节点策略页：实例列表/新建/编辑/下发/移除；`previewCommand`(命令预览)；`pollTaskDone`(轮询 task 终态) |
| `TemplateLibrary.vue` | 模板库：模板 CRUD + 实例化 |
| `Nodes.vue` | 节点管理 |
| `ExpertMode.vue` | 专家终端 |

## 关键语义（易踩坑）

1. **三层校验**：前端 saveInst + 后端 `ValidateFields`(→rulespec.Validate) + 编译器 `compileInstance`(→rulespec.Validate)，一致拦截。
2. **MARK 白名单**：`rulespec.IsMarkWhitelist` 判定（MARK+源+端口）。编译器自动生成 3 条规则：mangle 打标(MARKMANGLE,按端口) + filter 白名单放行(MARKACL-FWD/IN,按源+标) + 兜底 DROP。落内置链，group_id=0。**无"单纯打标"**。
3. **两套方向**：普通规则方向从组 `CustomChain.Parent` 继承（仅审计）；MARK 白名单方向用 `Direction` 字段（FORWARD/INPUT 决定 ACL 链）。**非 MARK 动作 Direction 必须为空**（rulespec 校验 + route 强制清空 + 编译器兼容旧数据）。
4. **dispatch 全量同步**：`CompileForNode` 编译所有 enabled 实例，Agent 全量 flush+重建。applied 由 `handleResult` 在 Agent 确认后更新（成功 enabled 对应 applied，失败全部 false）。
5. **移除保护期**：applied=true 移除 → enabled=false+pending_delete=true → dispatch → Confirm 物理删 / Rollback 恢复。`pending_delete_task_id` 精确关联 task。
6. **模板 vs 实例**：实例从模板全量复制参数(独立快照)；`SyncedTemplateUpdatedAt` 驱动 drift 检测。

## 已知技术债

- `agent/driver/nftables` 4 个测试失败（`b988355` 给 iptables 加 ESTABLISHED 放行未同步 nftables 测试）。
- 数据库残留 6 条无源 MARK 模板（249 测试机）。
