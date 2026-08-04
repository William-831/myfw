# 远程部署调试文档

## 1. 实际联调环境

- 远程：`192.168.80.249`，目录 `/home/myFW`
- Controller：Docker（host 编译挂载），:8080 Web / :9090 gRPC
- Agent：systemd，同机接入

## 2. 部署拓扑

```
[Controller:Docker] :8080 Web / :9090 gRPC
       |
   [Agent:systemd]（同机接入）
       |
   iptables MYFW 链
```

- **Controller**：Docker Compose（host 编译二进制挂载）
- **Agent**：裸机 systemd（静态编译，无 Docker/CGO）
- **数据库**：dev SQLite，prod MySQL/OceanBase（env 注入）

## 3. 前置准备

- **Controller 主机**：Docker + docker-compose、Go 1.25+（host 编译）、Node 20+（本地构建前端）
- **Agent 主机**：Linux + root（操作 Netfilter）、iptables/nftables

## 4. 开发环境（SQLite 本地跑通）

```bash
make gen-ca              # 生成 dev CA
make dev-controller      # 启动 Controller（SQLite，:8080/:9090）
make dev-agent           # 编译并启动 Agent（另终端，需 root）
```

## 5. Controller 部署（Docker，host 编译挂载）

构建约定：本地仅编辑 + push，远程 Linux 编译。

```bash
# 远程编译二进制（vendor 离线）
GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -trimpath -o dist/myfw-controller ./cmd/controller

# 前端（本地构建后上传 web/dist）
cd web && npm run build

# 启动（挂载二进制+前端+配置+CA+数据）
docker-compose up -d
```

docker-compose.yml 挂载：

| 宿主路径 | 容器路径 | 说明 |
|---|---|---|
| `./dist/myfw-controller` | `/usr/local/bin/myfw-controller` | host 编译二进制 |
| `./web/dist` | `/var/www/myfw` | 前端静态 |
| `./configs/controller-container.yaml` | `/etc/myfw/config.yaml` | 配置 |
| `./dev-ca` | `/etc/myfw/ca` | CA 证书 |
| `./data` | `/var/lib/myfw` | SQLite dev.db |

数据库切换：env `MYFW_DB_DRIVER=mysql MYFW_DB_DSN=...`（生产 OceanBase）。

## 6. Agent 部署（裸机 systemd）

```bash
make build-agent-linux    # 交叉编译（静态）

scp dist/myfw-agent-linux-amd64 root@<node>:/usr/local/bin/myfw-agent
scp deploy/systemd/myfw-agent.service root@<node>:/etc/systemd/system/
scp deploy/systemd/install-agent.sh root@<node>:/opt/

ssh root@<node> "bash /opt/install-agent.sh && systemctl enable --now myfw-agent"
```

## 7. 打包替换升级流程

本地（Windows git bash，项目根）：

```bash
# 打包源码（git archive，不含 vendor/node_modules）
git archive --format=tar.gz -o /tmp/myfw-src.tar.gz HEAD
scp /tmp/myfw-src.tar.gz root@192.168.80.249:/tmp/
```

远程（root@192.168.80.249）：

```bash
cd /home/myFW
tar xzf /tmp/myfw-src.tar.gz

# 编译 Controller 二进制（vendor 离线）
GOFLAGS=-mod=vendor CGO_ENABLED=0 go build -trimpath -o dist/myfw-controller ./cmd/controller

# 重启 Controller 容器
docker restart myfw-controller
```

前端（本地构建上传，远程无 node）：

```bash
cd web && npm run build
tar czf - -C web/dist . | ssh root@192.168.80.249 "cd /home/myFW/web/dist && rm -rf * && tar xzf -"
```

浏览器 Ctrl+F5 强刷生效。

## 8. 首次接入与 Agent 重新接入

**首次接入**：

1. Web「新增节点」获取一次性 bootstrap token
2. Agent 配置 `dev-agent.yaml` 填 token + CA 证书
3. 启动 Agent -> bootstrap complete，status=PENDING
4. Web approve -> ACTIVE

**数据库重建后重新接入**（Controller 数据库为空时，Agent 需重新 bootstrap）：

1. Web「新增节点」拿一次性 bootstrap token
2. Agent 配置填 token，删旧证书（`mv agent.crt agent.crt.bak`）
3. 启动 Agent -> bootstrap complete，status=PENDING
4. Web approve -> ACTIVE

Agent 由 systemd 管理：`systemctl restart myfw-agent`，日志 `journalctl -u myfw-agent -f`。

## 9. 升级与回滚

- **升级**：上传新二进制 + 前端，`docker restart myfw-controller`
- **回滚（保护期）**：下发后 5 分钟内，Web 保护期面板点「回滚」，Agent 恢复变更前快照

## 10. 常见运维

```bash
docker logs -f myfw-controller              # Controller 日志
journalctl -u myfw-agent -f                 # Agent 日志
docker exec -it myfw-controller sh          # 进入容器
ssh root@<node> "iptables -S | grep MYFW"   # 查看节点规则
bash scripts/rebootstrap-agents.sh          # CA 丢失时重新 bootstrap
```
