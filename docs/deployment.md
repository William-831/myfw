# 部署指南

> 版本：v0.3
> 更新日期：2026-07-27
> 配套文档：[design.md](./design.md)
>
> **部署形态约定**：
> - Controller：Docker Compose；host 编译二进制后挂载（绕过 docker build 拉基础镜像）
> - 数据库：当前部署用 SQLite；生产可切换 MySQL/OceanBase（外部资源，环境变量注入，规划中）
> - Agent：裸机 systemd，不提供容器镜像

---

## 目录

- [1. 部署拓扑](#1-部署拓扑)
- [2. 前置准备](#2-前置准备)
- [3. 开发环境（SQLite，本地跑通）](#3-开发环境sqlite本地跑通)
- [4. Controller 侧部署（docker-compose，接外部 OB）](#4-controller-侧部署docker-compose接外部-ob)
- [5. Agent 侧部署（裸机 systemd）](#5-agent-侧部署裸机-systemd)
- [6. 首次接入流程](#6-首次接入流程)
- [7. 升级与回滚](#7-升级与回滚)
- [8. 常见运维操作](#8-常见运维操作)

---

## 1. 部署拓扑

```
                    ┌─────────────────────────────┐
                    │  OceanBase (外部现成资源)      │
                    │  由 DBA / 平台方提供          │
                    │  仅暴露给 Controller 主机     │
                    │  :2881 mysql 协议            │
                    └──────────────▲──────────────┘
                                   │ MYFW_DB_DSN 注入
                                   │
┌─────────── 管理机 (一台,可以是云主机) ─────────────────┐
│                                  │                    │
│  ┌────────────────┐              │                    │
│  │  Controller    │──────────────┘                    │
│  │  Docker        │                                   │
│  │  :8080 web     │                                   │
│  │  :9090 grpc    │                                   │
│  └────────┬───────┘                                   │
│           │                                           │
│  volumes: /opt/myfw/{ca, controller-data}             │
└───────────┼───────────────────────────────────────────┘
            │
            │  mTLS gRPC
            │  Agent 主动连
   ┌────────┼──────────┬──────────────┬───────────────┐
   ▼        ▼          ▼              ▼               ▼
[节点 A]  [节点 B]  [节点 C]        [节点 N]         ...
 systemd   systemd    systemd        systemd
 myfw-agent  myfw-agent  myfw-agent  myfw-agent
```

**端口清单**：

| 组件 | 端口 | 协议 | 暴露范围 |
|---|---|---|---|
| Controller Web | 8080 | HTTPS | 管理员浏览器可达 |
| Controller gRPC | 9090 | mTLS/gRPC | 所有 Agent 可达 |
| OceanBase | 2881 | MySQL 协议 | **仅** Controller 主机可达（由外部 OB 侧的 ACL 保证） |

**Agent 侧不监听任何端口**，只出方向连接 Controller。

**OB 的部署与运维不属于本项目范围**：连接串、账号、库名、网络可达性、备份、扩容等都由 OB 提供方保障，本项目只消费。

---

## 2. 前置准备

### 2.1 Controller 主机

- Linux（Ubuntu 22.04+ / Debian 12+ / CentOS 8+ 均可）
- 已安装：
  - Docker Engine ≥ 24.0
  - Docker Compose Plugin ≥ 2.20
- 一个可解析到本机的域名（推荐），或至少一个稳定 IP
- 开放入方向：`8080/tcp`（Web）、`9090/tcp`（gRPC）
- 出方向能访问 **外部 OB** 的 `2881/tcp`

### 2.2 外部 OceanBase（不由本项目部署）

需要由 OB 提供方给出：

- 一个可用的 OB 集群或租户（MySQL 协议兼容层已开启）
- 连接串（host / port / user / password）
- 一个专属数据库（推荐名字 `myfw`），账号对该库拥有 DDL + DML 权限
- 网络可达性：Controller 主机能连到 OB 的 `2881`（或实际端口）

### 2.3 Agent 主机

- Linux（内核 ≥ 3.10，实际 4.x+ 更好）
- 已安装 `iptables` 或 `nftables` 其中之一（Agent 会自动探测）
- 有 `systemd`
- 有 `/etc/machine-id`（现代发行版默认都有）
- 出方向能访问 Controller 的 `9090/tcp`

### 2.4 资源建议

| 组件 | CPU | 内存 | 磁盘 |
|---|---|---|---|
| Controller | 2 vCPU | 2 GB | 20 GB（不含 OB） |
| Agent | 忽略 | 50 MB 常驻 | 100 MB |

> OB 资源由 OB 提供方规划，不在本文档范围。

---

## 3. 开发环境（SQLite，本地跑通）

用于开发者本机跑通、写测试、Demo 演示。**不要用于生产**。

> **构建约定（2026-07-27 起）**：本地仓库仅维护纯净源代码，下列 `go run` / `go build` / `make` 等编译、测试、打包命令统一在远程 Linux 服务器上执行；本地只做代码编辑与 `git commit/push`。开发数据库 `dev.db`、CA 证书目录 `dev-ca/` 等运行时产物均落在远程服务器，不进入 git。

### 3.1 启动 Controller（本地进程,不用 Docker）

```bash
cd go-iptablesops

# 数据库走 SQLite,DB 文件落在项目根目录 dev.db
export MYFW_DB_DRIVER=sqlite
export MYFW_DB_DSN=./dev.db

# 开发用的 CA / 证书目录,首次运行会自动生成一套自签 CA
export MYFW_CA_DIR=./dev-ca

# 启动
go run ./cmd/controller --config configs/controller.dev.yaml
```

首次启动会:

1. 在 `./dev.db` 里跑一次 AutoMigrate,建好所有表;
2. 在 `./dev-ca/` 下生成开发用的 CA + 服务端证书(仅用于开发,不要用到生产);
3. 监听 `:8080` (Web) 和 `:9090` (gRPC)。

### 3.2 启动一个本地 Agent 陪跑

```bash
# 编译 Agent
go build -o dist/myfw-agent ./cmd/agent

# 从 Controller Web 上「新增待接入节点」拿一个 bootstrap_token
# 写一份最小配置
cat >dev-agent.yaml <<EOF
controller:
  endpoint: 127.0.0.1:9090
  tls:
    ca_file: ./dev-ca/ca.pem
    cert_file: ./dev-agent.crt
    key_file: ./dev-agent.key
  bootstrap_token: "<刚拿到的 token>"
node:
  labels: [dev]
EOF

# 开发态直接前台跑,方便看日志
sudo ./dist/myfw-agent --config dev-agent.yaml
```

> 本地 Agent 也会真实操作宿主机 Netfilter,建议在虚拟机 / 容器里的完整 Linux 环境跑,不要直接在开发机上试规则下发。

### 3.3 数据库切换到 OB

改环境变量即可,业务代码零改动:

```bash
export MYFW_DB_DRIVER=mysql
export MYFW_DB_DSN="myfw:pass@tcp(ob.internal:2881)/myfw?charset=utf8mb4&parseTime=true&loc=Local"
go run ./cmd/controller --config configs/controller.dev.yaml
```

---

## 4. Controller 侧部署（docker-compose，接外部 OB）

### 4.1 目录结构

```
/opt/myfw/
├── docker-compose.yaml
├── .env                         # 敏感环境变量（含 OB 连接串），0600 权限
├── controller/
│   ├── config.yaml              # Controller 非敏感配置
│   └── data/                    # 挂载卷：Controller 运行时数据
└── ca/                          # 私有 CA 根密钥 + 证书（0600，妥善备份！）
    ├── ca.key
    ├── ca.pem
    └── server.{crt,key}         # Controller 的服务端证书
```

> **注意**：目录里 **没有 `ob/`** —— OB 是外部资源，本机不落任何 OB 数据。

### 4.2 生成私有 CA 和 Controller 服务端证书

Controller 首次启动前，需要生成一套 CA。这里给一份最小可用的 openssl 脚本：

```bash
mkdir -p /opt/myfw/ca && cd /opt/myfw/ca

# 1. CA 根密钥 + 自签证书（有效期 10 年）
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=myfw-ca" -out ca.pem

# 2. Controller 服务端证书(有效期 2 年)
#    SAN 里写 Controller 的对外访问域名/IP
openssl genrsa -out server.key 4096
openssl req -new -key server.key -subj "/CN=controller" -out server.csr

cat >server.ext <<'EOF'
subjectAltName = @alt_names
[alt_names]
DNS.1 = controller.example.com
IP.1  = 10.0.0.10
EOF

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.crt -days 730 -sha256 -extfile server.ext

chmod 0600 ca.key server.key
rm server.csr server.ext
```

> **重要**：`ca.key` 是整个系统的信任根。必须离线备份一份到安全介质，泄漏等于所有 Agent 都可以被冒充。

### 4.3 Controller 配置文件

Controller 的配置分两部分：

- **非敏感配置**放 `config.yaml`（挂只读进容器）；
- **敏感配置**（尤其是 OB 连接串）放 `.env`，由 docker-compose 注入环境变量。

`/opt/myfw/controller/config.yaml`:

```yaml
server:
  web:
    listen: :8080
  grpc:
    listen: :9090
    tls:
      ca_file: /etc/myfw/ca/ca.pem            # 用于校验 Agent 客户端证书
      cert_file: /etc/myfw/ca/server.crt
      key_file: /etc/myfw/ca/server.key
      client_auth: require_and_verify         # 强制校验客户端证书

# 数据库连接从环境变量注入,这里只写非敏感的连接池参数
database:
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 30m

ca:
  key_file: /etc/myfw/ca/ca.key
  cert_file: /etc/myfw/ca/ca.pem
  agent_cert_ttl: 8760h                       # Agent 客户端证书默认 1 年
  agent_cert_renew_before: 720h               # 剩 30 天时允许续签

bootstrap:
  token_ttl: 15m                              # 一次性接入令牌有效期

audit:
  retention_days: 365
```

`/opt/myfw/.env`（0600 权限，**不要**提交到 git）:

```bash
# 数据库(生产:外部 OB;开发:改成 sqlite)
MYFW_DB_DRIVER=mysql
MYFW_DB_DSN=myfw_user:REPLACE_ME@tcp(ob.internal.example.com:2881)/myfw?charset=utf8mb4&parseTime=true&loc=Local

# 也可以把其他要覆盖的配置放这里,前缀 MYFW_
# MYFW_SERVER_WEB_LISTEN=:8080
```

**优先级**：`.env` 里的环境变量 > `config.yaml` 里同名字段 > 内置默认值。

### 4.4 docker-compose.yaml

`/opt/myfw/docker-compose.yaml`:

```yaml
version: "3.9"

services:
  controller:
    image: myfw/controller:latest   # 由本项目构建
    container_name: myfw-controller
    restart: unless-stopped
    ports:
      - "8080:8080"                 # Web
      - "9090:9090"                 # gRPC (mTLS)
    env_file:
      - .env                        # 注入 MYFW_DB_DSN 等敏感配置
    volumes:
      - /opt/myfw/controller/config.yaml:/etc/myfw/config.yaml:ro
      - /opt/myfw/ca:/etc/myfw/ca:ro
      - /opt/myfw/controller/data:/var/lib/myfw
      - /opt/myfw/dist/myfw-controller:/usr/local/bin/myfw-controller:ro   # host 编译二进制挂载（绕过 docker build）
    command: ["--config", "/etc/myfw/config.yaml"]
    # 出方向要能到外部 OB(2881);如果 OB 只对特定网段开放,这里可能需要
    # extra_hosts 或加 network_mode: host,按实际环境调整
```

**说明**：

- 没有 `depends_on: ob` —— OB 是外部资源；
- 没有独立 `networks` —— 默认 bridge 就能出到外网，如果 OB 在内网需要按实际网络策略调整；
- Controller 启动时会尝试连 OB，连不上直接失败退出（不静默降级）。

### 4.5 启动

```bash
cd /opt/myfw
chmod 0600 .env                       # 敏感文件权限收紧

docker compose pull
docker compose up -d

# 观察日志
docker compose logs -f controller
```

第一次启动 Controller 会：

1. 读取 `MYFW_DB_DRIVER=mysql` + `MYFW_DB_DSN`，连接外部 OB；
2. 在 OB 上执行 schema 迁移（AutoMigrate + 版本化脚本）；
3. 加载 CA；
4. 开始监听 8080 (Web) 和 9090 (gRPC)。

**如果 OB 连不上**：Controller 会打出明确错误并退出（不会静默回落到 SQLite）。

浏览器访问 `https://controller.example.com:8080` 完成初始管理员账号设置。

---

## 5. Agent 侧部署（裸机 systemd）

### 5.1 二进制构建（在开发机 / CI 上执行）

Agent 必须**静态编译**，产出单一二进制。

```bash
cd go-iptablesops

# 交叉编译 Linux amd64（无 CGO,纯静态）
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/myfw-agent-linux-amd64 ./cmd/agent

# arm64 版本(树莓派 / ARM 服务器)
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
  go build -trimpath -ldflags="-s -w" \
  -o dist/myfw-agent-linux-arm64 ./cmd/agent

# 校验:确认是静态链接
file dist/myfw-agent-linux-amd64
# 期望输出:  ... statically linked, ...
```

**为什么坚持静态**：

- Agent 部署到大量异构 Linux 发行版，动态链接会踩 glibc 版本不匹配的坑；
- 静态二进制 = 一个文件搞定，`scp` 上去就能跑。

### 5.2 分发产物

一次分发到目标机器的内容：

| 文件 | 目标路径 | 权限 |
|---|---|---|
| `myfw-agent` | `/usr/local/bin/myfw-agent` | 0755 root:root |
| `myfw-agent.service` | `/etc/systemd/system/myfw-agent.service` | 0644 root:root |
| `agent.yaml` | `/etc/myfw-agent/agent.yaml` | 0600 root:root |
| `ca.pem` | `/etc/myfw-agent/ca.pem` | 0644 root:root |

私钥和客户端证书**不在**首次分发里，它们由 Agent 首次注册时自动生成并落盘。

### 5.3 一键安装脚本（推荐）

在 Controller Web 上「新增待接入节点」后会显示这样一段脚本，复制到目标机器执行即可：

```bash
#!/usr/bin/env bash
set -euo pipefail

CONTROLLER="controller.example.com:9090"
BOOTSTRAP_TOKEN="eyJhbGciOi..."         # 一次性,15 分钟过期
DOWNLOAD_URL="https://controller.example.com:8080/download/agent/linux-amd64"

# 1. 下载二进制
curl -fsSL -o /usr/local/bin/myfw-agent "$DOWNLOAD_URL"
chmod 0755 /usr/local/bin/myfw-agent

# 2. 目录 + CA 证书
install -d -m 0755 /etc/myfw-agent
install -d -m 0700 /var/lib/myfw-agent
curl -fsSL -o /etc/myfw-agent/ca.pem "https://controller.example.com:8080/pki/ca.pem"

# 3. 配置文件
cat >/etc/myfw-agent/agent.yaml <<EOF
controller:
  endpoint: ${CONTROLLER}
  tls:
    ca_file: /etc/myfw-agent/ca.pem
    cert_file: /etc/myfw-agent/agent.crt
    key_file: /etc/myfw-agent/agent.key
  bootstrap_token: "${BOOTSTRAP_TOKEN}"
node:
  labels: []
EOF
chmod 0600 /etc/myfw-agent/agent.yaml

# 4. systemd unit
cat >/etc/systemd/system/myfw-agent.service <<'EOF'
[Unit]
Description=MYFW Agent
Documentation=https://controller.example.com:8080/docs
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/myfw-agent --config /etc/myfw-agent/agent.yaml
Restart=on-failure
RestartSec=3s

User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=false

# 数据目录
ReadWritePaths=/var/lib/myfw-agent /etc/myfw-agent

[Install]
WantedBy=multi-user.target
EOF

# 5. 启动
systemctl daemon-reload
systemctl enable --now myfw-agent

# 6. 观察日志
journalctl -u myfw-agent -f
```

### 5.4 Agent 首次启动做的事

1. 读取 `/etc/myfw-agent/agent.yaml`；
2. 生成或读取 `node.id`（`/var/lib/myfw-agent/node.id`）；
3. 生成客户端私钥 + CSR（私钥永不出机）；
4. 用 `bootstrap_token` 通过 mTLS 连 Controller，交上 CSR + 候选 node_id + 机器指纹 + 能力探测结果；
5. Controller 返回签发好的客户端证书，Agent 写入 `agent.crt`；
6. Agent 从配置里清除 `bootstrap_token`（一次性令牌立即失效）；
7. 进入正常心跳 + 等待管理员在 Web 上「接入」；
8. 管理员点「接入」后，状态从 `PENDING` → `ACTIVE`，开始接收规则下发任务。

---

## 6. 首次接入流程

以下是一台新机器从零到接入完成的完整流程：

```
[管理员浏览器]              [Controller]                     [目标 Linux 主机]
     │                          │                                   │
     │ ① 新增待接入节点            │                                   │
     ├──────────────────────────▶│                                   │
     │                          │ 生成 bootstrap_token               │
     │  返回一键安装脚本            │  (15min TTL)                     │
     │◀──────────────────────────┤                                   │
     │                          │                                   │
     │  ② 复制脚本                │                                   │
     └──────────────────────────────────────────────────────────────▶│
                                                                    │ ③ 下载二进制
                                                                    │   写配置 + unit
                                                                    │   systemctl start
                                                                    │
                                                                    │ ④ Agent 首次注册
                                 ┌◀──────────────────────────────────┤
                                 │ bootstrap_token + CSR + 指纹       │
                                 │                                   │
                                 │ 校验 token → 签发客户端证书          │
                                 │ 状态置 PENDING                     │
                                 ├──────────────────────────────────▶│
                                 │ 返回客户端证书 + node_id            │
                                 │                                   │ ⑤ 落盘证书
                                 │                                   │   清空 token
                                 │                                   │   开始心跳
     │  ⑥ 看到 PENDING 节点        │                                   │
     │◀──────────────────────────┤                                   │
     │  核对机器指纹                │                                   │
     │  点「接入」                  │                                   │
     ├──────────────────────────▶│                                   │
     │                          │ 绑定证书指纹到 node_id              │
     │                          │ 状态置 ACTIVE                       │
     │                          ├──────────────────────────────────▶│
     │                          │ 允许规则下发                        │ ⑦ 可以下发规则了
```

---

## 7. 升级与回滚

### 7.1 Controller 升级

```bash
cd /opt/myfw
# 更新镜像 tag
sed -i 's|myfw/controller:.*|myfw/controller:v1.2.0|' docker-compose.yaml
docker compose pull controller
docker compose up -d controller
docker compose logs -f controller
```

Controller 是无状态的（所有状态都在 OB 里），升级过程中：

- 已有 Agent 会短暂断连，然后自动重连；
- Agent 侧防火墙规则**不受影响**（Agent 只是失去了管控通道，规则仍在内核里正常工作）。

### 7.2 Controller 回滚

改回旧 tag，`docker compose up -d controller` 即可。因为数据在 OB，业务状态保留。

> ⚠️ 涉及 schema 迁移的版本回滚需要看具体版本的迁移说明，不能盲目回滚。

### 7.3 Agent 升级

```bash
# 1. 分发新二进制
scp dist/myfw-agent-linux-amd64 target:/tmp/myfw-agent.new

# 2. 在目标机器上原子替换 + 重启
ssh target 'bash -s' <<'EOF'
install -m 0755 /tmp/myfw-agent.new /usr/local/bin/myfw-agent
systemctl restart myfw-agent
journalctl -u myfw-agent -n 20 --no-pager
EOF
```

Agent 重启期间：

- **已生效的防火墙规则不受影响**（Netfilter 规则由内核持有，Agent 只是管控进程）；
- 跳转规则不会被删除（Agent 优雅退出时不清理 MYFW 命名空间）；
- 重启后 Agent 会重新连 Controller、上报状态、同步差异。

### 7.4 Agent 回滚

保留上一版本二进制，`install` 覆盖回去 + `systemctl restart` 即可。

---

## 8. 常见运维操作

### 8.1 查看 Agent 状态

```bash
# 服务状态
systemctl status myfw-agent

# 实时日志
journalctl -u myfw-agent -f

# 最近 200 行
journalctl -u myfw-agent -n 200 --no-pager
```

### 8.2 查看 Agent 实际生效的规则

```bash
# iptables 后端
iptables -S | grep MYFW
iptables -t nat -S | grep MYFW

# nftables 后端
nft list table inet myfw
```

### 8.3 强制 Agent 重新与 Controller 全量同步

```bash
systemctl restart myfw-agent
```

Agent 启动时会向 Controller 请求全量规则清单并 diff 本地状态。

### 8.4 手工删除 Agent（下线一台机器）

**顺序很重要**：先在 Web 上把节点状态改为「下线」→ Controller 会下发一个「清理 MYFW 命名空间」的任务 → Agent 执行完后停止服务 → 然后再删本地文件。

```bash
# 等 Web 上显示"已清理"后再执行:
systemctl disable --now myfw-agent
rm -f /usr/local/bin/myfw-agent
rm -f /etc/systemd/system/myfw-agent.service
rm -rf /etc/myfw-agent /var/lib/myfw-agent
systemctl daemon-reload
```

如果跳过「Web 上下线」直接删 Agent，MYFW 命名空间下的规则和跳转会**残留在 Netfilter 里**，需要手工清理（`iptables -F MYFW-INPUT` 之类）。

### 8.5 CA 密钥泄漏应急

**最坏情况**。处理步骤：

1. 立即停 Controller（`docker compose stop controller`）；
2. 用备份的离线 CA 或者生成一套新 CA；
3. 用新 CA 重签 Controller 服务端证书；
4. Controller 数据库里所有 Agent 记录标记为「需要重接入」；
5. 所有 Agent 需要重新走一次 bootstrap 流程（生成新的 `bootstrap_token`，重新分发）。

这也是为什么第 3.2 节强调 `ca.key` 必须离线备份 + 严格控制访问。

### 8.6 备份

**Controller 主机上要备份的**：

- `/opt/myfw/ca/` （CA 根密钥 + 证书，最重要，建议加密后离线备份）
- `/opt/myfw/controller/config.yaml`
- `/opt/myfw/.env`（含 OB 连接串，加密保存）

**OB 数据的备份不在本项目范围**：由 OB 提供方按其运维规范执行（快照、binlog、跨机房复制等）。本项目只需在灾难恢复时能拿到一份可用的 OB（同 schema、同数据）即可。

**Agent 主机上要备份的**：

- 什么都不用备。Agent 挂了直接重装一次即可，节点身份走「重绑定」流程恢复（见 design.md § 13.3.4）。

---

## 附：文件权限速查表

| 路径 | 属主 | 权限 | 备注 |
|---|---|---|---|
| `/opt/myfw/ca/ca.key` | root | 0600 | **绝密**，离线备份 |
| `/opt/myfw/ca/ca.pem` | root | 0644 | 公开，随 Agent 分发 |
| `/opt/myfw/ca/server.key` | root | 0600 | Controller 服务端私钥 |
| `/opt/myfw/controller/config.yaml` | root | 0640 | 含 DB DSN |
| `/etc/myfw-agent/agent.yaml` | root | 0600 | 首次含 bootstrap_token |
| `/etc/myfw-agent/agent.key` | root | 0600 | Agent 客户端私钥 |
| `/etc/myfw-agent/agent.crt` | root | 0644 | |
| `/etc/myfw-agent/ca.pem` | root | 0644 | |
| `/var/lib/myfw-agent/node.id` | root | 0600 | 节点身份种子 |
