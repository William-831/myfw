# Linux 网络防火墙统一管理平台 · 设计文档

> 版本：v0.4
> 更新日期：2026-07-20
> 定位：面向个人运维使用的企业级 Linux 网络防火墙集中管理平台
>
> **部署形态约定**：Controller 以 Docker 方式部署；Agent **仅以裸机 systemd 形态部署**，不提供容器镜像，也不做 K8s DaemonSet 适配。
>
> **安全基线**：Controller ↔ Agent 通信 **强制 mTLS**，明文连接一律拒绝。节点身份采用「Agent 生成候选 ID + Controller 审核入库 + 证书指纹绑定」的三段式方案（详见第 13 节）。
>
> **数据层约定**：生产使用现成的 OceanBase（外部资源，通过环境变量注入连接串）；开发环境使用 SQLite。业务代码统一走 GORM，不做数据库自动降级（详见第 2 节）。

---

## 目录

- [1. 系统定位与总体架构](#1-系统定位与总体架构)
- [2. 数据持久化层](#2-数据持久化层)
- [3. 技术栈与模块划分](#3-技术栈与模块划分)
- [4. Firewall Driver 抽象层](#4-firewall-driver-抽象层)
- [5. Agent 能力探测机制](#5-agent-能力探测机制)
- [6. 策略模型与规则编译](#6-策略模型与规则编译)
- [7. 规则所有权隔离（MYFW 命名空间）](#7-规则所有权隔离myfw-命名空间)
- [8. 入口跳转与流量接管](#8-入口跳转与流量接管)
- [9. 功能能力范围](#9-功能能力范围)
- [10. 规则管理模式](#10-规则管理模式)
- [11. 安全变更控制](#11-安全变更控制)
- [12. Watchdog 漂移检测](#12-watchdog-漂移检测)
- [13. 通信设计](#13-通信设计)
- [14. 网络状态与流量采集](#14-网络状态与流量采集)
- [15. 部署方案](#15-部署方案)
- [16. 系统总览](#16-系统总览)
- [附录 A：术语表](#附录-a术语表)
- [附录 B：待明确的设计点](#附录-b待明确的设计点)

---

## 1. 系统定位与总体架构

本系统旨在构建一套面向 Linux 服务器环境的统一网络防火墙管理平台，通过 Web 可视化控制台实现对多台 Linux 主机网络访问策略、防火墙规则、NAT 转发以及流量状态的集中化管理。

**定位**：个人运维使用的企业级网络管理工具。

**架构思想**：采用云控制面思想，**控制面（Controller）与执行面（Agent）分离**。

| 角色 | 职责 |
|---|---|
| **Controller**（中心化） | 用户认证、Web 接口服务、策略管理、规则编排、审批流程、任务调度、状态持久化、统一控制逻辑 |
| **Agent**（分布式） | 节点环境探测、防火墙规则执行、网络状态采集、流量数据采集、执行结果反馈 |

通过控制面与执行面的解耦：

- 具备管理多节点 Linux 主机的能力；
- 防止单节点故障影响整体管理能力；
- 对宿主上的 Docker 环境保持感知与兼容（不覆盖 DOCKER 链），但 Agent 本身**只以裸机 systemd 形态部署**。

---

## 2. 数据持久化层

### 2.1 存储职责

- **生产存储引擎**：**OceanBase（OB）**，走 MySQL 协议兼容层，由 GORM 访问。
- **开发存储引擎**：**SQLite**，仅用于本地开发和自测，不用于生产。
- **存储内容**：
  - 服务器节点信息
  - 防火墙策略模型
  - 规则版本
  - 审批记录
  - 操作审计日志
  - Agent 状态信息
  - 任务执行记录
  - 规则 Hash 校验信息
  - 流量统计数据
- **一致性原则**:Controller 不保存任何不可恢复的核心状态,数据库为最终可信数据源。

### 2.2 数据层驱动策略(Dev / Prod 二态)

系统对数据库的访问统一走 GORM,通过配置切换后端,业务代码零感知。

| 环境 | Driver | 用途 | 是否用于生产 |
|---|---|---|---|
| 开发环境 | SQLite (`modernc.org/sqlite`,纯 Go 免 CGO) | 本地跑通、单测、Demo | ❌ |
| 生产环境 | OceanBase (MySQL 协议,`gorm.io/driver/mysql`) | 正式部署 | ✅ |

**关键约束**:

- **OB 是外部现成资源**,不在本项目部署范围内,Controller 通过环境变量注入连接串;
- **不做数据库自动降级**:配置指向 OB 但连不上时,Controller 启动失败并明确报错,不静默回落到 SQLite;
- **schema 迁移一份 SQL**:所有 DDL 用 GORM AutoMigrate + 手写迁移脚本双轨,两种 Driver 都能跑通(避免使用 OB/MySQL 独占的语法);
- **SQLite 只出现在开发者机器上**:不打进 Controller 生产镜像的运行链路,配置文件默认指向 MySQL 协议。

### 2.3 配置注入方式

Controller 的数据库连接**优先从环境变量读取**,配置文件字段作为兜底:

| 环境变量 | 含义 | 示例 |
|---|---|---|
| `MYFW_DB_DRIVER` | `mysql`(生产/OB) 或 `sqlite`(开发) | `mysql` |
| `MYFW_DB_DSN` | 数据源连接串 | `user:pass@tcp(ob-host:2881)/myfw?charset=utf8mb4&parseTime=true&loc=Local` |
| `MYFW_DB_MAX_OPEN_CONNS` | 最大连接数(可选) | `50` |
| `MYFW_DB_MAX_IDLE_CONNS` | 空闲连接数(可选) | `10` |

**优先级**:环境变量 > 配置文件 > 内置默认(SQLite `./dev.db`,仅开发)。

**为什么优先环境变量**:

- 生产环境 OB 连接串通常含密码,不适合落到镜像里的配置文件;
- docker-compose / K8s Secret / systemd EnvironmentFile 都能自然注入;
- 让 Controller 镜像本身与部署环境解耦。

### 2.4 容灾特性

- Controller 运行在 Docker 中出现异常退出、重启、迁移、重新部署时,可直接从 OB 加载最新状态;
- 恢复节点关系、策略配置、未完成任务;
- 避免传统 Web 管理系统依赖本地文件或内存状态导致的数据丢失。

利用 OceanBase 事务能力保证 **规则变更 / 审批流程 / 版本记录** 三者之间的数据一致性。SQLite 仅用于开发,不承担这一职责。

---

## 3. 技术栈与模块划分

### 3.1 后端

- 语言：**Go**
- Web 框架：**Gin**（REST API）
- ORM：**GORM**（连接 OceanBase）

### 3.2 前端

- 框架：**Vue3 + TypeScript**
- UI 库：**Element Plus**
- 呈现能力：服务器资产、防火墙状态、网络策略、规则命中情况、实时流量、连接状态、历史操作记录。

### 3.3 后端模块划分

| 模块 | 说明 |
|---|---|
| 用户认证模块 | 登录、权限、令牌管理 |
| 节点资产管理模块 | 节点注册、能力、状态、分组 |
| 防火墙策略管理模块 | 策略 CRUD、版本 |
| 规则编译模块（Rule Compiler） | 策略模型 → 标准规则对象 |
| 任务调度模块 | 变更任务下发、状态跟踪 |
| 审批管理模块 | 审批流、差异对比 |
| 版本控制模块 | 规则版本、快照、回滚 |
| 审计日志模块 | 全过程审计 |
| 流量分析模块 | 流量、连接、命中数据 |

---

## 4. Firewall Driver 抽象层

系统核心设计采用 **Firewall Driver 防火墙驱动抽象层**，将上层网络安全策略与底层 Linux 防火墙技术完全解耦。

### 4.1 分层职责

```
┌────────────────────────────────────────────┐
│           安全策略模型（业务视角）             │
├────────────────────────────────────────────┤
│      Rule Compiler（规则编译，Controller）    │
├────────────────────────────────────────────┤
│      标准化防火墙规则对象（中间语言）           │
├────────────────────────────────────────────┤
│      Firewall Driver 接口（Agent 侧）        │
├────────────────────────────────────────────┤
│ IptablesDriver │ NftablesDriver │ eBPFDriver│
└────────────────────────────────────────────┘
```

- Controller **不直接生成 iptables 命令**；
- Controller 维护统一的网络策略模型；
- Rule Compiler 将策略转换为标准化规则对象；
- Agent 根据当前节点环境选择对应 Driver 执行。

### 4.2 Driver 统一接口能力

- 规则创建 / 删除
- 链管理
- 规则同步
- 配置读取
- 状态检测
- 备份恢复
- Hash 校验

### 4.3 第一阶段实现

| Driver | 适用场景 | 实现方式 |
|---|---|---|
| **IptablesDriver** | 传统 Linux 环境 | iptables-legacy / iptables-nft / 相关 Go 库 |
| **NftablesDriver** | 现代 Linux 系统 | nft 原生接口 / nftables 库直接操作 Netfilter |

### 4.4 未来扩展

- **eBPF Driver**：实现更加高级的数据面控制能力；
- 扩展新 Driver **无需修改** Controller 和策略模型。

---

## 5. Agent 能力探测机制

Agent 启动后 **不基于内核版本简单判断**，而是通过能力探测机制自动判断当前节点支持能力：

- Linux 发行版
- iptables 版本
- iptables backend 类型（legacy / nft）
- nft 命令支持情况
- Netfilter 能力
- Docker 环境
- Kubernetes 环境
- 当前系统已有防火墙组件状态

**决策示例**：

- 老旧 Linux → `iptables-legacy`
- 支持 nft backend 的现代系统 → `iptables-nft` 或 `NftablesDriver` 

Agent 将节点能力信息同步至 Controller，由 Controller 保存节点能力模型。

**收益**：平台可同时管理不同 Linux 发行版和不同防火墙技术环境，实现真正的跨平台防火墙管理能力。

---

## 6. 策略模型与规则编译

### 6.1 策略模型字段

管理员配置的是 **抽象安全策略**，不是 iptables 参数。

| 字段 | 说明 |
|---|---|
| 方向 | INBOUND / OUTBOUND / FORWARD |
| 源地址 | IP / CIDR / 分组 |
| 目标地址 | IP / CIDR / 分组 |
| 协议类型 | TCP / UDP / ICMP / ANY |
| 端口范围 | 单端口 / 范围 |
| 动作类型 | ACCEPT / DROP / REJECT / MARK / DNAT / SNAT … |
| 优先级 | 数值序 |
| 描述信息 | 可读说明 |
| 生效节点 | 节点 / 节点组 |

### 6.2 编译示例

同一条「允许 TCP 22 端口访问」的策略：

- **IptablesDriver**：生成 `INPUT` 链下的 ACCEPT 规则；
- **NftablesDriver**：转换为 `inet family` 下的 chain rule。

业务层完全不依赖底层实现。

---

## 7. 规则所有权隔离（MYFW 命名空间）

为解决 Linux 环境中多来源防火墙规则并存的问题，系统设计严格的规则所有权隔离机制。

### 7.1 命名空间

| 后端 | 命名空间形式 |
|---|---|
| iptables | 自定义链：`MYFW-INPUT` / `MYFW-FORWARD` / `MYFW-NAT` … |
| nftables | 独立 `MYFW table` 与 chain |

### 7.2 权限边界

| 规则来源 | Agent 权限 |
|---|---|
| MYFW 前缀（平台生成） | **读 / 写 / 删** |
| 非 MYFW 前缀（root 手工、DOCKER 链、KUBE 链、其他系统服务） | **仅读取和展示，不改不删** |

**核心原则**：Agent 只拥有自身命名空间范围内的规则管理权限，实现多来源规则共存。

---

## 8. 入口跳转与流量接管

为了将管理规则接入 Linux 网络处理流程，Firewall Driver 负责维护入口跳转逻辑。

| 后端 | 接管方式 |
|---|---|
| iptables | 在 `INPUT` / `OUTPUT` / `FORWARD` 等系统链中插入跳转规则，将流量导入 MYFW 管理链 |
| nftables | 通过独立 table、chain 和 hook 机制接管 |

**安全策略**：

- 执行跳转规则操作前，对目标链、规则位置、已有规则上下文进行严格检测；
- **不覆盖** 其他系统规则；
- **不改变** Docker、Kubernetes 原有网络逻辑；
- 外部规则发生变化时，系统 **不强制恢复整个防火墙**，只维护自身管理范围。

---

## 9. 功能能力范围

系统聚焦 **访问控制与网络转发**，**不做复杂流量限速**。

### 9.1 支持的 Netfilter 表

- `filter`：访问控制
- `nat`：地址转换
- `mangle`：数据包标记
- `raw`：基础控制

### 9.2 支持的链

`INPUT` / `OUTPUT` / `FORWARD` / `PREROUTING` / `POSTROUTING`

### 9.3 支持的能力

- 入 / 出方向访问控制
- 转发控制
- DNAT 端口映射
- SNAT 地址转换
- IP 黑名单 / 白名单
- 网段限制
- 协议限制
- 端口限制
- 基于 `mangle MARK` 的数据包标签

### 9.4 联动能力

通过 MARK 标记，可进一步与 Linux Traffic Control、策略路由或其他网络系统联动，实现更加复杂的网络控制。

---

## 10. 规则管理模式

系统提供两种规则管理模式，**共享同一策略模型**，保证不会产生数据分裂。

| 模式 | 目标用户 | 展示形式 |
|---|---|---|
| **普通模式** | 日常运维 | 云安全组式：源 / 目标 / 协议 / 端口 / 动作 |
| **专家模式** | 高级管理员 | 底层 Driver 实际生成的规则结构（iptables/nftables 的 table/chain/rule） |

---

## 11. 安全变更控制

所有防火墙修改操作必须经过审批流程。

### 11.1 变更流程

```
提交变更 ─▶ 生成任务 + 保存前后策略差异
        └─▶ 审批
              └─▶ Agent：保存当前节点防火墙快照
                    └─▶ Driver.Apply()
                          └─▶ 进入「确认保护期」
                                ├─ 超时未确认 ─▶ Driver.Rollback() → 上一稳定版本
                                └─ 已确认 ─▶ 记录新稳定版本
```

### 11.2 关键机制

- **审批前置**：无审批不可 Apply。
- **快照兜底**：Apply 前自动保存节点当前状态。
- **确认保护期**：防止错误策略导致服务器失联。
- **自动 Rollback**：超时未确认自动回滚。
- **全过程审计**：操作者、目标节点、变更内容、执行结果、恢复记录均入库。

---

## 12. Watchdog 漂移检测

Agent 内部设计 Watchdog 机制，用于持续检测自身管理区域状态。

- **检测对象**：MYFW 管理链、入口跳转规则、规则 Hash 值。
- **检测触发**：定期扫描。
- **发现漂移**（人为修改 / 删除 / 变动）：
  - 上报告警到 Controller；
  - 根据配置：自动恢复 或 等待管理员确认。
- **不检测**：Docker / Kubernetes / 管理员手工规则 —— 避免误报。

---

## 13. 通信设计

### 13.1 基础形态

- **连接模式**：**Agent 主动连接 Controller**，Agent 不暴露管理端口。
- **协议**：**gRPC 双向 Streaming 长连接**。
- **用途**：
  - 节点注册
  - 心跳检测
  - 任务下发
  - 执行结果返回
  - 状态同步
  - 实时数据传输
- **可靠性**：
  - 断线自动重连；
  - 任务缓存；
  - 离线运行能力。
- **Controller 不可用时**：Agent 保持当前已生效策略继续运行，恢复连接后同步最新状态。

### 13.2 传输层安全（强制 mTLS）

Controller ↔ Agent 之间的 gRPC 通信 **强制启用双向 TLS**，不提供明文开关。

**PKI 模型**：

- Controller 内置一套私有 CA（`myfw-ca`），密钥由 Controller 管理员在初始化阶段生成，长期离线保存副本；
- Controller 服务端证书由 `myfw-ca` 签发，SAN 包含公网/内网入口的域名或 IP；
- 每一个 Agent 都有一张独立的**客户端证书**，由 `myfw-ca` 签发，`CN` 或 `URI SAN` 中携带该节点的 `node_id`；
- Agent 侧同时校验 Controller 服务端证书链；Controller 侧同时校验 Agent 客户端证书链 + 证书指纹绑定关系（见 13.3）。

**证书分发**：

- 首次装机时，管理员在 Controller Web 上「新增待接入节点」→ Controller 生成一次性 `bootstrap_token`（有效期短，一次性使用）；
- 管理员把 `bootstrap_token` + `ca.pem` 一起随 Agent 二进制分发到目标节点；
- Agent 首次启动时用 `bootstrap_token` 通过 mTLS-CA 校验（Controller 服务端证书由 `ca.pem` 校验）向 Controller 发起注册请求，Controller 返回该 Agent 的**正式客户端证书**；
- 后续所有连接都使用正式客户端证书，`bootstrap_token` 立即失效。

**证书轮换**：

- 客户端证书默认有效期 1 年；
- Agent 在证书剩余有效期低于 30 天时，通过已有 mTLS 通道向 Controller 请求续签；
- 私钥不出宿主机，Agent 本地生成 CSR 发送。

**明文/降级**：

- 一律拒绝，Controller 只监听 TLS 端口；
- 证书失效 / 指纹不匹配 / CA 不匹配 → 直接断连并告警。

### 13.3 节点身份与 ID 生成策略

节点身份采用 **「Agent 生成候选 ID + Controller 审核入库 + 证书指纹绑定」** 三段式：

#### 13.3.1 候选 ID 生成（Agent 侧）

Agent 首次启动时执行：

```
candidate_id = "n_" + hex( SHA256( machine_id || hostname || random_salt ) )[0:32]
```

- `machine_id`：读取 `/etc/machine-id`；
- `hostname`：读取 `/etc/hostname`；
- `random_salt`：Agent 首次启动时生成的 32 字节随机数，落盘保存；
- 结果**只是候选**，未经 Controller 审核前不具备任何管理权限。

生成后立即写入 `/var/lib/myfw-agent/node.id`（0600 权限，root 属主），后续启动一律读文件，**不再重算**。

加 `random_salt` 的意义：防止同一云镜像克隆多台机器时 `machine_id` 重复导致候选 ID 冲突。

#### 13.3.2 首次注册（Agent → Controller）

Agent 携带以下信息发起 `Register` 请求：

| 字段 | 说明 |
|---|---|
| `bootstrap_token` | 一次性接入令牌 |
| `candidate_id` | 上一步生成的候选 ID |
| `machine_fingerprint` | machine-id、主机名、内核版本、CPU 架构、网卡 MAC 列表 |
| `capabilities` | 能力探测结果（iptables/nft 版本、Docker/K8s 存在与否等，见第 5 节） |

Controller 侧：

- 校验 `bootstrap_token` 有效；
- 在 OB 中插入一条 `node` 记录，状态 = `PENDING`；
- 返回正式客户端证书 + Controller 分配的最终 `node_id`（**默认直接采用 candidate_id**，冲突时追加短随机后缀）；
- **PENDING 状态下 Agent 只能心跳，不接收任何规则下发任务**。

#### 13.3.3 审核入库（管理员在 Web 上操作）

管理员在 Web 控制台看到 `PENDING` 节点，核对机器指纹后点击「接入」：

- 状态改为 `ACTIVE`；
- 将 Agent 客户端**证书指纹（SHA-256 of DER）**绑定到 `node_id`；
- 之后每次 gRPC 连接，Controller 都校验：
  1. mTLS 证书链有效；
  2. 证书 CN/SAN 中的 `node_id` 与 OB 中存的一致；
  3. 证书指纹与 OB 中存的一致。
- 三项任一不匹配 → 拒绝连接 + 审计告警。

#### 13.3.4 重装 / 迁移场景

| 场景 | 表现 | 处理 |
|---|---|---|
| Agent 二进制升级，`/var/lib/myfw-agent/node.id` 保留 | `node_id` 不变，证书不变 | 无感知 |
| 系统重装，`node.id` 丢失，但 `machine_id` 未变 | Agent 会生成新的候选 ID | Controller 侧管理员触发「重绑定」，把旧 `node_id` 的证书指纹更新为新 Agent 的指纹；机器指纹（machine-id）作为佐证 |
| 更换机器 / 云镜像克隆 | `machine_id` 变化 | 视为全新节点，走完整注册流程；旧 `node_id` 在 Web 上手动归档 |
| 证书泄漏 | 管理员在 Web 上「吊销」 | Controller 立即拒绝该指纹连接；下次以 `bootstrap_token` 重新签发 |

#### 13.3.5 身份相关的审计事件

以下事件必须落审计日志：

- 新节点注册（含机器指纹快照）；
- 节点从 PENDING 变为 ACTIVE；
- 证书重绑定；
- 证书吊销；
- 证书指纹不匹配的连接尝试。

---

## 14. 网络状态与流量采集

### 14.1 职责分离

| 能力 | 实现路径 |
|---|---|
| 规则操作 | Firewall Driver |
| 网络状态 / 流量采集 | Linux Netlink / `/proc` / conntrack |

### 14.2 采集指标

- 网卡流量
- 连接数量
- 规则命中次数
- 数据包统计
- TOP 网络访问信息

### 14.3 未来扩展

通过 eBPF 采集模块，实现类似 **Cilium Hubble** 的网络流量可视化能力。

---

## 15. 部署方案

### 15.1 Controller

- 独立 Docker 服务；
- 可通过 Docker Compose 或 Kubernetes 部署。

### 15.2 Agent（裸机 systemd，唯一支持方式）

Agent **只支持裸机部署**，不提供容器化运行方式。

**设计目标**：

- 一个静态编译的二进制 + 一个 systemd unit 文件即可完成部署；
- 目标机器不需要 Docker、不需要 Go 运行时、不需要额外的动态库依赖。

**产物形态**：

| 产物 | 说明 |
|---|---|
| `myfw-agent` | 静态编译的 Go 二进制，默认安装到 `/usr/local/bin/myfw-agent` |
| `myfw-agent.service` | systemd unit 文件，安装到 `/etc/systemd/system/myfw-agent.service` |
| `/etc/myfw-agent/agent.yaml` | 配置文件（Controller 地址、节点标识、TLS 证书等） |
| `/var/lib/myfw-agent/` | 运行时数据目录（本地缓存、快照等） |

**典型安装流程**：

```bash
# 1. 分发二进制
install -m 0755 myfw-agent /usr/local/bin/myfw-agent

# 2. 写配置
mkdir -p /etc/myfw-agent
cat >/etc/myfw-agent/agent.yaml <<'EOF'
controller:
  endpoint: controller.example.com:9090

  # mTLS 必填,不提供明文开关
  tls:
    ca_file: /etc/myfw-agent/ca.pem              # 校验 Controller 服务端证书
    cert_file: /etc/myfw-agent/agent.crt         # Agent 客户端证书,首次为空,注册后写入
    key_file: /etc/myfw-agent/agent.key

  # 一次性接入令牌,首次注册后 Agent 会自动清空这一行
  bootstrap_token: "eyJhbGciOi..."

node:
  # node_id 首次启动时由 Agent 自动生成候选值并落盘到 /var/lib/myfw-agent/node.id
  # 不需要在配置里指定
  labels: [prod, edge]
EOF

# 3. 写 systemd unit
cat >/etc/systemd/system/myfw-agent.service <<'EOF'
[Unit]
Description=MYFW Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myfw-agent --config /etc/myfw-agent/agent.yaml
Restart=on-failure
RestartSec=3s

# Agent 必须能操作 Netfilter，直接 root 运行
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# 4. 启动
systemctl daemon-reload
systemctl enable --now myfw-agent
```

**运行时特性**：

- **权限**：以 `root` 运行，直接拥有 `CAP_NET_ADMIN` / `CAP_NET_RAW`，可直接操作 iptables / nftables；
- **拉起**：`Restart=on-failure`，进程崩溃自动重启；
- **日志**：写入 journald，通过 `journalctl -u myfw-agent` 查看；
- **升级**：替换二进制 + `systemctl restart myfw-agent`，无需重启机器，已生效的规则不受影响（Controller 挂了也一样）。

### 15.3 明确不做的事

- ❌ Agent 不提供 Docker 镜像；
- ❌ Agent 不支持 Kubernetes DaemonSet 部署；
- ❌ Agent 不通过容器方式分发。

**理由**：Agent 本质是宿主 Netfilter 的直接操作者，容器化后必须 `host network` + `privileged`，已经等价于宿主进程，容器化只增加复杂度不带来隔离收益。裸机 systemd 是最直接的形态。K8s 场景不在本项目范围内。

---

## 16. 系统总览

```
                 ┌───────────────────────────────┐
                 │        Web Console            │
                 │   Vue3 + TS + Element Plus    │
                 └──────────────┬────────────────┘
                                │  HTTPS / REST
                 ┌──────────────▼────────────────┐
                 │         Controller             │
                 │  Gin + GORM (Go)               │
                 │  Auth / Asset / Policy /       │
                 │  Compiler / Task / Approval /  │
                 │  Version / Audit / Traffic     │
                 └──────┬──────────────┬─────────┘
                 gRPC   │              │  GORM
              双向 Streaming           ▼
                        │       ┌──────────────┐
                        │       │  OceanBase   │
                        │       └──────────────┘
        ┌───────────────┼───────────────┐
        │               │               │
   ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
   │ Agent A │     │ Agent B │     │ Agent N │
   │ Driver  │     │ Driver  │     │ Driver  │
   │ Watchdog│     │ Watchdog│     │ Watchdog│
   │ Collect │     │ Collect │     │ Collect │
   └────┬────┘     └────┬────┘     └────┬────┘
        │               │               │
   Linux Netfilter  Linux Netfilter  Linux Netfilter
   (MYFW namespace)
```

**核心价值**：

| 问题 | 解决手段 |
|---|---|
| 状态可靠性 | OceanBase 持久化 |
| 底层技术演进 | Firewall Driver 抽象 |
| 规则冲突 | MYFW 命名空间隔离 |
| 操作安全 | 审批 + 快照 + 自动 Rollback |
| 运维复杂度 | Web 可视化 + 云安全组式策略 |

最终形成一个基于 **Controller + Agent 架构、OceanBase 持久化、Firewall Driver 抽象、多源规则隔离、策略编译、安全审批、流量分析** 于一体的 Linux 网络安全管理平台，能够统一管理 Linux 主机、Docker 环境以及未来的 Kubernetes 节点，是一个**轻量级、可扩展、生产级**的网络防火墙控制平台。

---

## 附录 A：术语表

| 术语 | 说明 |
|---|---|
| Controller | 控制面服务，负责策略、审批、任务、持久化 |
| Agent | 执行面服务，部署在每个 Linux 节点，负责规则执行与采集 |
| Firewall Driver | 底层防火墙抽象，屏蔽 iptables / nftables / eBPF 差异 |
| Rule Compiler | Controller 侧的策略 → 标准化规则对象编译器 |
| MYFW | 平台专属命名空间前缀，用于规则所有权隔离 |
| Watchdog | Agent 内的漂移检测组件 |
| 确认保护期 | 变更 Apply 后等待 Controller 确认的时间窗，超时自动回滚 |

---

## 附录 B：待明确的设计点

以下为后续版本需进一步定义的问题：

1. **规则优先级 / 顺序语义**：iptables（数组序）与 nftables（handle 序）差异较大，需明确策略 `priority` 到两种 Driver 的映射规则。
2. **多节点批量下发策略**：审批通过后是串行灰度还是并行下发？部分节点失败的语义？
3. **Rollback 粒度**：整机快照 vs 仅 MYFW 命名空间 —— 默认建议后者，需明确边界。
4. **Agent 自升级**：升级过程中的规则连续性与跳转规则不丢失。
5. **IPv6 支持**：策略模型与 Driver（`ip6tables` / nftables `ip6` / `inet` family）需要预留字段。
6. **审计与合规**：审计日志的保留策略、导出格式、外部 SIEM 对接。
7. **权限模型**：多用户 / RBAC / 节点分组授权（当前仅描述「个人运维」定位）。
