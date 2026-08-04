# Linux 网络防火墙统一管理平台 · 设计文档

## 1. 系统定位与总体架构

集中管理多节点 Linux iptables 的平台。Controller（Web+gRPC）集中编排，Agent（裸机 systemd）落地执行，规则收敛在 `MYFW` 命名空间，不动 DOCKER/KUBE/用户手工规则。

```
[Web UI] --HTTP--> [Controller] --gRPC(mTLS)--> [Agent] --iptables--> [MYFW 链]
                         |
                   [SQLite/MySQL]
```

- **Controller**：Gin Web(:8080) + gRPC(:9090)，策略编排、审批、保护期、审计
- **Agent**：主动连 Controller，落地 iptables，watchdog 防漂移
- **数据库**：dev SQLite，prod MySQL/OceanBase（env 注入）

## 2. 数据持久化层

- GORM AutoMigrate，SQLite(dev)/MySQL(prod) 二态驱动
- 配置注入：config.yaml + env 覆盖（MYFW_DB_DRIVER/DSN）
- 容灾：SQLite 落盘持久化；MySQL 外部托管

核心模型：
- `Node`/`NodeCapability`：节点 + 能力
- `PolicyTemplate`：策略模板（可复用骨架）
- `NodePolicyInstance`：节点实例（独立参数快照，`applied` 标记已下发）
- `CustomChain`：策略组（= 自定义子链）
- `AddressGroup`：地址组（-> ipset）
- `Mark`：标记定义
- `Task`：变更任务（状态机）
- `AuditLog`：审计日志
- `Policy`/`PolicyVersion`：旧模型（迁移/统计/引用检查保留）

## 3. 技术栈与模块划分

- 后端：Go（Gin + gRPC + GORM + slog）
- 前端：Vue 3 + Element Plus + Pinia
- 通信：gRPC + mTLS + HMAC 防重放

后端模块：
- `internal/controller/`：compiler(编译) / policy(CRUD) / server(HTTP路由) / task(状态机) / stream(gRPC) / audit(审计) / auth / pki
- `internal/agent/`：bootstrap / capability / conn / driver(iptables/nftables) / handler / watchdog
- `internal/model`：数据模型
- `internal/security`：mTLS/HMAC/会话
- `internal/pki`：证书签发

## 4. Firewall Driver 抽象层

Driver 统一接口：`Init / Apply / Hash / Snapshot / Restore / EnsureJumps`。

- **IptablesDriver**：MYFW 命名空间，期望态同步（flush+重建），ipset 地址组
- **NftablesDriver**：backend 切换（capability 探测）

Apply 流程：`syncSets`(ipset) -> flush 父链 + ESTABLISHED 首条 -> `syncCustomChains`(创建+挂载) -> `pruneCustomChains`(孤儿清理) -> 按序 `-A` 规则 -> Hash

## 5. 策略模型与规则编译

两级模型：**PolicyTemplate**（模板库，无节点）+ **NodePolicyInstance**（节点实例，独立参数快照）。

- 实例化时全量复制模板参数，模板修改不影响已存在实例（drift 检测 + 手动同步）
- 编译只读实例，按 priority 排序生成 CompiledRule
- MARK 白名单实例（group_id=0）落内置链，其他动作必选策略组

## 6. 规则所有权隔离（MYFW 命名空间）

三层链结构：
```
系统链(INPUT/FORWARD/PREROUTING…) --jump--> MYFW 父链 --jump--> 策略组子链(MYFW-<组名>) --规则
```

MYFW 父链（driver 管理）：

| 表 | 父链 | 系统链 |
|---|---|---|
| filter | MYFW-INPUT / FORWARD / OUTPUT | INPUT / FORWARD / OUTPUT |
| nat | MYFW-PREROUTING / POSTROUTING | PREROUTING / POSTROUTING |
| mangle | MYFW-MANGLE | PREROUTING |

权限边界：只管 MYFW 命名空间，不碰 DOCKER/KUBE/用户链。策略组=子链，父链按 priority 顺序 jump。

## 7. 入口跳转与流量接管

- **ensureJump**：系统链 position 1 插入 jump 到 MYFW 父链（幂等）
- **ESTABLISHED 首条**：MYFW-INPUT/FORWARD/OUTPUT 首条放行已建立连接，防 Docker 回包被误杀
- **共存**：MYFW jump 与 DOCKER 链共存，靠 ESTABLISHED 兜底回包

## 8. 功能能力范围

- **表**：filter / nat / mangle
- **链**：MYFW-INPUT/FORWARD/OUTPUT/PREROUTING/POSTROUTING/MANGLE + 用户子链
- **动作**：ACCEPT / DROP / REJECT / MARK / DNAT / SNAT
- **MARK 白名单**：方向(FORWARD/INPUT) + 源(IP/地址组) + 端口 + 标记，自动 3 规则（打标 mangle MARKMANGLE + 放行 filter MARKACL-FWD/IN + 兜底 DROP），group_id=0 落内置链

## 9. 规则管理模式

- **节点策略**：实例配置（表单）+ 专家终端
- **专家模式**：裸 iptables 命令通道（命令行 + 规则拓扑可视化）

## 10. 安全变更控制

变更流程：提交 -> 审批 -> 下发 -> 保护期 -> 确认/回滚

task 状态机：
```
pending_approval -> dispatching -> applying -> confirm_wait -> confirmed(生效)
                                              -> rolled_back(回滚) / failed
```

- **保护期**：apply 成功后 5 分钟确认窗口，超时自动回滚快照
- **回滚**：Agent 用变更前快照恢复 MYFW 命名空间
- **单用户体系**：root 跳过审批（auto_approve），保留保护期
- **禁用场景**：applied 语义（禁用已下发实例保留 applied=true），change_type=disable，-D 移除命令

## 11. Watchdog 漂移检测

- 定期对比节点实际 hash vs 期望 hash，不一致触发 drift 上报 + sync
- jump 顺序自愈：docker/k8s 重启导致 jump 错乱时，EnsureJumps 重排 position 1

## 12. 通信设计

- Agent 主动连 Controller（长连接，gRPC 流）
- 强制 mTLS（Controller 签发 Agent 证书）
- 节点身份：Agent 生成候选 ID -> bootstrap token 注册 -> 管理员 approve -> ACTIVE
- 应用层会话：HMAC 防重放 + IP 钉扎 + 证书轮换

## 13. 部署方案

- **Controller**：Docker Compose，host 编译二进制挂载（绕过 docker build 拉镜像）
- **Agent**：裸机 systemd（deploy/systemd/），静态编译无 CGO
