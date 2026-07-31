# Linux 网络防火墙统一管理平台 · 设计文档

> 版本：v0.5
> 更新日期：2026-07-27
> 定位：面向个人运维使用的企业级 Linux 网络防火墙集中管理平台
>
> **部署形态约定**：Controller 以 Docker 方式部署；Agent **仅以裸机 systemd 形态部署**，不提供容器镜像，也不做 K8s DaemonSet 适配。
>
> **安全基线**：Controller ↔ Agent 通信 **强制 mTLS**，明文连接一律拒绝。节点身份采用「Agent 生成候选 ID + Controller 审核入库 + 证书指纹绑定」的三段式方案（详见第 13 节）。
>
> **数据层约定**：当前部署使用 SQLite（开发与远程部署均用）；生产可切换 MySQL/OceanBase（通过环境变量注入连接串，规划中）。业务代码统一走 GORM，不做数据库自动降级（详见第 2 节）。

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
| 通信安全模块 | gRPC 会话令牌（HMAC-SHA256）、防重放、IP 钉扎、证书自动轮换（详见 §13.4） |
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

### 4.4 地址组与 sets 下发

`Apply(ctx, *RuleSet)` 接收完整期望态（rules + sets），地址组（`AddressGroup`）编译为 `AddressSet` 随 RuleSet 原子下发：

- iptables driver：`ipset create/flush/add` 同步 `MYFW-<name>` 集合（hash:net）；
- nftables driver：`nft add set/flush/add element` 同步 set（ipv4_addr + interval）；
- `compileRule` 将 `source_group`/`destination_group` 编译为 `-m set --match-set` / `ip saddr @set`，`match_mark` 编译为 `-m mark --mark` / `meta mark`，`MARK` 动作编译为 `--set-mark` / `meta mark set`。

### 4.5 未来扩展

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

### 6.1 三级关联模型（模板/实例分离）

策略模型采用 **三级关联结构**：「策略组 + 策略模板 + 节点策略实例」，将规则骨架（模板）与节点实例（带具体参数）的生命周期彻底分离，消除"模板改了影响已应用节点"的混乱：

**策略组（CustomChain）** = 底层自定义子链 `MYFW-<name>`，承载调度属性：

| 字段 | 说明 |
|---|---|
| 名称 | 子链名（节点链 `MYFW-<name>`） |
| 钩子方向（parent） | 父链 MYFW-INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING/MANGLE |
| 全局优先级（priority） | 父链中 jump 到本子链的顺序，值小排前 |
| 表 | filter/nat/mangle（与父链一致） |

**策略模板（PolicyTemplate）** = 可复用规则骨架，归属策略组，**不绑定节点**：

| 字段 | 说明 |
|---|---|
| 所属组（group_id） | 关联策略组（必填），继承方向/子链 |
| 协议/端口/源/目的/地址组 | 默认匹配参数（实例化时复制给实例） |
| 动作类型 | ACCEPT / DROP / REJECT / MARK / DNAT / SNAT |
| 标记值 / 匹配标记 | MARK 打标 / 匹配已打标 |
| 优先级 | 组内排序（小者先评估） |

**节点策略实例（NodePolicyInstance）** = 节点上的规则实例，创建时从模板**全量复制参数**，编译只读实例：

| 字段 | 说明 |
|---|---|
| 模板引用（template_id） | 引用模板，用于 drift 检测与手动同步 |
| 节点（node_id） | 目标节点（单节点） |
| 规则参数 | 从模板复制的全量参数（独立快照，模板改不影响） |
| 启用（enabled） | 一键启停，需重新下发生效 |

> 模板修改**不影响**已存在实例（实例独立保存参数快照）；实例与模板参数不一致时标记 drift，用户可一键同步模板最新参数。旧 `Policy` 表保留作迁移源与审计，不再参与编译。
>
> **同步语义**：同步时数值/调度字段（组 / mark / 优先级等通用参数）始终覆盖；字符串字段（源/目的 IP、协议、端口、动作等）仅当模板有值时才覆盖--模板为空意味着该字段是节点特有参数（由实例自定义，如节点 IP），同步保留实例原值，避免清空实例配置。drift 检测沿用同一语义（模板空字段不参与比较）。

### 6.2 编译示例

同一条「允许 TCP 22 端口访问」的策略：

- **IptablesDriver**：生成 `INPUT` 链下的 ACCEPT 规则；
- **NftablesDriver**：转换为 `inet family` 下的 chain rule。

业务层完全不依赖底层实现。

---

## 7. 规则所有权隔离（MYFW 命名空间）

为解决 Linux 环境中多来源防火墙规则并存的问题，系统设计严格的规则所有权隔离机制。**所有平台策略不直接操作内置链**，全部收敛在 Agent 维护的 MYFW 自定义链内；内置链仅在顶部插一条 jump 将流量导入 MYFW 管理链，从而与 Docker、Kubernetes 或手工配置的系统规则共存且互不干扰。

### 7.1 命名空间

| 后端 | 命名空间形式 |
|---|---|
| iptables | 6 条自定义链：filter 表 `MYFW-INPUT`/`MYFW-OUTPUT`/`MYFW-FORWARD`、nat 表 `MYFW-PREROUTING`/`MYFW-POSTROUTING`、mangle 表 `MYFW-MANGLE` |
| iptables 地址组 | `ipset` 集合 `MYFW-<name>`（hash:net，多 CIDR） |
| iptables 自定义子链 | 策略组 `MYFW-<name>`（从父链 jump，`Policy.group_id` 归属，见 §7.4） |
| nftables | 独立 `myfw` table + chain（inet/ip family） |
| nftables 地址组 | nft `set` `MYFW-<name>`（type ipv4_addr + flags interval） |

### 7.2 规则落点映射

策略组的钩子方向（parent）决定流量入口的父链，条目规则落于组对应的子链：

| 组钩子方向 | 父链（调度层） | 子链（业务层） |
|---|---|---|
| MYFW-INPUT | filter/MYFW-INPUT | MYFW-<组名> |
| MYFW-OUTPUT | filter/MYFW-OUTPUT | MYFW-<组名> |
| MYFW-FORWARD | filter/MYFW-FORWARD | MYFW-<组名> |
| MYFW-PREROUTING | nat/MYFW-PREROUTING | MYFW-<组名> |
| MYFW-POSTROUTING | nat/MYFW-POSTROUTING | MYFW-<组名> |
| MYFW-MANGLE | mangle/MYFW-MANGLE | MYFW-<组名> |

### 7.3 权限边界

| 规则来源 | Agent 权限 |
|---|---|
| MYFW 前缀（平台生成） | **读 / 写 / 删** |
| 非 MYFW 前缀（root 手工、DOCKER 链、KUBE 链、其他系统服务） | **仅读取和展示，不改不删** |

**核心原则**：Agent 只拥有自身命名空间范围内的规则管理权限，实现多来源规则共存。

### 7.4 策略组调度（两级模型）

策略组（CustomChain）= 自定义子链 `MYFW-<name>`，是父链的调度单元。`syncCustomChains` 在 Apply 时创建子链（`-N` 幂等）+ 父链追加 jump（`-A` 幂等）+ flush 子链；`loadCustomChains` 按 `priority ASC` 排序，父链中 jump 到各子链的顺序由组优先级决定（值小排前）。

条目（Policy）通过 `group_id` 归属策略组，编译时 `Chain` 取组名、`Direction` 取组父链，规则落于 `MYFW-<组名>` 子链。`targetChainForRule` 不再回退落父链--`chain` 为空即报错，从机制上杜绝业务规则污染父链。

父链由此保持整洁：仅含基础设施优化规则（ESTABLISHED,RELATED 放行）+ 业务调度规则（按序 jump 子链），所有具体访问控制/NAT/标记规则落于子链，两者各司其职。

---

## 8. 入口跳转与流量接管

为了将管理规则接入 Linux 网络处理流程，Firewall Driver 负责维护入口跳转逻辑。

| 后端 | 接管方式 |
|---|---|
| iptables | 在 `INPUT`/`OUTPUT`/`FORWARD`/`PREROUTING`/`POSTROUTING` 系统链顶部插入 `-j MYFW-*`，将流量导入 MYFW 管理链 |
| nftables | 通过独立 `myfw` table、chain 和 hook 机制接管 |

### 8.1 顶部精准插入（ensureJump）

MYFW jump **始终保持在系统链 position 1**（先于 Docker 的 `DOCKER-USER`/`DOCKER`、K8s 的 `KUBE-*` 等规则生效），确保平台策略不被抢占：

- 校验系统链第一条规则是否为 `-j MYFW-*`，是则跳过；
- 否则删除现有任意位置的 MYFW jump（避免重复），再 `-I 1` 插到顶部；
- 每次 `Apply` 时执行；watchdog 定期校验自愈（抗 Docker/K8s 重启导致的顺序错乱，见 §12）。

### 8.2 ESTABLISHED 放行

`MYFW-INPUT`/`MYFW-FORWARD`/`MYFW-OUTPUT` 首条插 `-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`，放行已建立连接的回包。这是 MYFW-FORWARD 提前到 DOCKER 之前的必要前提——否则 Docker 回包不再被 docker 的 ESTABLISHED ACCEPT 放行，会因平台 DROP 策略断开现有连接。

### 8.3 共存原则

- **不覆盖** 其他系统规则；**不改变** Docker、Kubernetes 原有网络逻辑；
- 外部规则发生变化时，系统 **不强制恢复整个防火墙**，只维护自身管理范围。

---

## 9. 功能能力范围

系统聚焦 **访问控制与网络转发**，**不做复杂流量限速**。

### 9.1 支持的 Netfilter 表

- `filter`：访问控制
- `nat`：地址转换
- `mangle`：数据包标记

### 9.2 支持的链（MYFW 命名空间内）

`MYFW-INPUT` / `MYFW-OUTPUT` / `MYFW-FORWARD` / `MYFW-PREROUTING` / `MYFW-POSTROUTING` / `MYFW-MANGLE`

### 9.3 支持的能力

- 入 / 出 / 转发方向访问控制
- DNAT 端口映射 / SNAT 地址转换
- **地址组（白/黑名单）**：`AddressGroup` 维护多 CIDR 集合，编译为 `ipset`/`nft set`（`-m set --match-set` / `ip saddr @set`），一条规则匹配海量 CIDR，O(1) 查找
- 协议 / 端口限制
- **MARK 打标**（mangle）+ **match_mark 匹配**（filter）：打标与匹配正交，可组合联动

### 9.4 mark + 白名单联动

典型场景「仅白名单 IP 可访问打了 mark 的业务流量」：

1. 策略 A（mangle/MYFW-MANGLE）：给业务端口流量 `MARK --set-mark 100`
2. 策略 B（filter/MYFW-FORWARD）：`match_mark=100` + `source_group=whitelist` -> ACCEPT
3. 策略 C（filter/MYFW-FORWARD）：`match_mark=100` -> DROP（兜底）

按优先级顺序匹配：白名单 IP 的 mark=100 流量先 ACCEPT，其余落到 DROP。对 Docker 暴露端口流量（经 DNAT 走 FORWARD）同样适用——用宿主端口在 mangle 打标，FORWARD 匹配标 + 白名单，不依赖容器 IP。

---

## 10. 规则管理模式

系统策略入口拆为两个一级模块，**模板与实例分离**，避免"通用骨架"与"节点实例"混用：

| 模块 | 职责 |
|---|---|
| **策略模板库** | 维护可复用规则骨架（归属组，无节点），不涉及具体节点 |
| **节点策略** | 以节点为中心，展示该节点已生效实例，从模板实例化并填节点特有参数 |

### 10.1 节点级直操作收敛 MYFW

节点管理页的「编辑规则」（单条增删改插）只能操作 `MYFW-*` 链，拒绝直接操作 `INPUT`/`FORWARD`/`OUTPUT`/`PREROUTING`/`POSTROUTING` 等内置链。从入口堵住绕过平台直接改内置链，确保所有平台下发的规则都落在 MYFW 命名空间内。

### 10.2 节点策略：实例配置 + 专家终端

节点策略页提供两种模式（右上开关切换）：

- **实例配置模式**：双栏（左节点列表 / 右实例列表）。从模板实例化（全量复制参数）+ drift 角标（模板已更新）+ 一键同步 + 编辑参数（含 iptables 命令预览）+ 一键启停 + 节点下发（dispatch，走保护期）。
- **专家终端模式**：对节点敲裸 iptables 命令（REPL），见 §10.3。

### 10.3 专家模式：裸 iptables 命令通道（命令行 + 规则拓扑）

专家终端嵌入节点策略页，供高级管理员在节点上直接敲入 iptables 命令排障，并以“横向拓扑 + 纵向详情”的空间布局对应策略组“父链调度 / 子链执行”的层级关系：

- **协议**：`stream.proto` 新增 `ControllerToAgent.exec_command`（`ExecCommand{task_id, command}`），复用 `TaskResult` 回传（`ok`=exit 0，`message`=stdout/stderr）。
- **白名单**：Agent 侧 `handler.OnExec` 校验命令首 token 必须属于 iptables 族（`iptables`/`ip6tables`/`iptables-save`/`iptables-restore`/`nft`），拒绝任意 shell 命令，防止退化为 webshell。
- **命令行交互**：中部命令输入框回车提交 + ↑↓ 回溯历史 + 常用命令快捷按钮。输入时前端实时解析（`composables/useIptablesParse`）操作类型（`-A`/`-I`/`-D`/`-F`/`-P`/`-N`/`-X`）与目标链，于输入框下方提示归属。
- **规则拓扑（下方）**：专家终端置顶优先，下方为单一规则拓扑，呈父链 -> 子链 -> 规则两级折叠树。父链（六条 MYFW 父链，仅展示有子链的）来自 `GET /custom-chains`，规则来自 `GET /iptables/rules/:node_id` 节点实际规则（按优先级排列）。命令输入时浏览器高亮目标父链 + 子链定位归属；“一键折叠”切换全展开/全收起（层级可记忆恢复）；执行命令后自动刷新规则并展开受影响子链。
- **危险命令二次确认**：`-F`/`-P ... DROP`/`-X` 等清空/改默认策略/删链操作前端弹窗二次确认。
- **强审计**：每条命令经 `POST /api/v1/iptables/exec/:node_id` 下发，Controller 写审计日志（操作人/节点/命令/输出）。

> ⚠️ 此通道**绕过 MYFW 命名空间、快照、保护期**，`iptables -F`/`-P DROP` 等可导致节点失联且平台无法回滚。仅限高级管理员 knowingly 接受风险时使用，靠白名单 + 强审计 + 二次确认兜底。

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

### 11.3 当前简化：单用户 root 跳过审批（保留保护期）

当前为单用户体系（`admin` 即 root，未引入多用户/角色），审批环节按以下方式简化，但**保护期始终保留**（符合方案3：跳过审批不代表跳过保护期，保护期是最后一道安全防线，不应被绕过）：

- **跳过审批**：前端 apply 默认 `auto_approve=true`，提交后直接进入下发执行，不生成 `pending_approval` 待审批任务（root 自己审批自己无安全价值）。
- **保留保护期**：Agent Apply 成功后进入 `confirm_wait`，启动倒计时（默认 5 分钟）。管理员须在保护期内点"确认"才最终生效（释放 Agent 快照）；超时未确认或点"回滚"，Agent 自动恢复到变更前状态。
- **强审计留痕**：`Coordinator.Submit` 在 `AutoApprove=true` 时审计 detail 标记 `skip_approval=true` + `reason`；`task.applying_ok` 携带 `confirm_deadline`，`task.confirm`/`task.manual_rollback` 记录确认/回滚操作，事后可完整追溯。
- **未来扩展**：引入普通用户/多用户后，普通用户恢复完整审批流程，root 维持跳过审批；保护期对所有人生效。

### 11.4 保护期确认交互（前端）

保护期内任务通过全局角标 + 右侧滑出面板集中管理，避免弹窗打断工作流 + 防止遗忘确认导致超时回滚：

- **顶部角标**：Layout 顶部常驻 Clock 图标 + 数字角标（保护期内任务数），最后 60s 图标闪烁提醒临近超时。
- **右侧面板**：点击角标滑出 `el-drawer`，按任务列出策略名 / 节点IP / 倒计时进度条 / 确认/回滚按钮；10s 轮询刷新列表，1s 更新倒计时。
- **节点页辅助入口**：Nodes 状态列对有保护期任务的节点显示"待确认"标签，点击唤起面板。
- **审批中心对齐**：Approve 页支持 `confirm_wait` 状态筛选与确认/回滚操作。

> 专家模式裸命令通道（§10.2）绕过保护期，靠白名单 + 强审计 + 二次确认兜底。

---

## 12. Watchdog 漂移检测

Agent 内部设计 Watchdog 机制，用于持续检测自身管理区域状态。

- **检测对象**：MYFW 管理链、入口跳转规则、规则 Hash 值。
- **检测触发**：定期扫描。
- **发现漂移**（人为修改 / 删除 / 变动）：
  - 上报告警到 Controller；
  - 根据配置：自动恢复 或 等待管理员确认。
- **不检测**：Docker / Kubernetes / 管理员手工规则 —— 避免误报。

### 12.1 jump 顺序自愈

watchdog 定期（30s）校验各系统链 position 1 是否仍为 `-j MYFW-*`。Docker/K8s 重启后若 MYFW jump 被挤到后面，自动按 §8.1 的 ensureJump 逻辑重排回 position 1，确保平台策略始终先于 DOCKER/KUBE 生效。

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

- 客户端证书有效期由 Controller 配置 `ca.agent_cert_ttl` 决定（开发环境默认 1 年，内网生产可缩短）；
- Agent 侧 `internal/security/CertRotation` 组件后台检测证书临近过期（默认剩余不足有效期 20% 时），通过已有 mTLS 通道向 Controller 请求续签；
- 私钥不出宿主机，Agent 本地生成 EC P-256 密钥对与 CSR 发送，新证书原子落盘（先写临时文件再 rename，崩溃安全）。

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

### 13.4 应用层会话安全（internal/security）

在 mTLS 传输层之上，系统叠加一层**应用层会话安全**，用于纯内网环境下防御横向移动、指令伪造与重放攻击。该能力由 `internal/security` 模块统一实现，作为 gRPC 一元 / 流式拦截器接入。

**会话令牌**：

- Agent 注册成功后，Controller 为其签发轻量会话令牌（`SessionToken`），绑定 `node_id`、证书指纹、首次连接 IP；
- 令牌使用 HMAC-SHA256 签名（不引入 JWT 库，避免外部依赖），载荷形如 `nodeID|fingerprint|ip|issuedAt|expiresAt|nonce`；
- 后续请求通过 gRPC metadata 携带 `x-session-token` + `x-session-sig`。

**防重放**：每个令牌携带随机 nonce，Controller 侧 `SessionManager` 记录已消费的 nonce，重复 nonce 直接拒绝。

**IP 钉扎**：可选启用，将 `node_id` 绑定到首次连接 IP，IP 变化判定为可疑（横向移动征兆）并拒绝连接。

**Bootstrap 例外**：`Registration/Register` 方法走特殊认证路径（仅校验 bootstrap token），不要求会话令牌，保证首次接入可达。

**拦截器组合**：`SecureInterceptor` 统一执行「mTLS 证书提取 node_id → IP 钉扎 → 会话令牌验证 → 注入 node_id 到 ctx」流程，业务 handler 通过 `security.NodeIDFromContext(ctx)` 取用。

> 说明：会话令牌与 mTLS **叠加而非替代**--mTLS 提供传输加密与证书身份，会话令牌提供应用级防重放与行为绑定。开发环境可通过 `DisableTLS` 降级为仅 metadata 传 `x-node-id`，仅用于本地联调，生产一律强制 mTLS。

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
- 节点 iptables 规则快照（filter / nat / mangle / raw 各链，区分 MYFW 命名空间）

### 14.3 规则上报与同步

Agent 通过 gRPC 双向流的 `IptablesRules` 消息上报节点当前 iptables 规则（按 table / chain 组织），Controller 可下发 `SyncRulesRequest` 主动请求上报。上报内容持久化到 `IptablesRule` 模型，供 Web 控制台「专家模式」展示节点底层规则并与期望态对比（见 §10）。该能力与 Firewall Driver 的 MYFW 命名空间规则隔离互补：Driver 管理平台下发规则，规则上报展示全量规则（含非 MYFW 的系统规则，只读）。

### 14.4 未来扩展

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
