# 远程调试部署方案

> 用途:在远程 Linux 上部署 Controller(Docker 容器)+ Agent(工作目录编译)进行功能联调。
> 本地 Windows **仅编辑代码与 git**,不做任何编译/部署。
> 配套文件:`deploy/docker/Dockerfile.debug`、`docker-compose.debug.yml`、`configs/controller-debug.yaml`。
>
> 部署形态约定:
> - **Controller**:Docker 容器(alpine 运行时),二进制/前端/CA/DB 全部挂载宿主机产物。
> - **前端**:本地 `npm run build` 产物 `web/dist` 上传后挂载进容器,与镜像解耦(持久化)。
> - **Agent**:远程工作目录 `go build`,前台 `sudo` 运行,不用 systemd。
> - **数据库**:SQLite(挂载持久化),不接 OceanBase。
> - **同步**:本地攒改动 → 大版本/核心功能升级 → 经确认 → push gitee → 远程 pull。

---

## 实际联调环境(192.168.80.249)

> 实际联调机连接信息,免下次重复提供。密码不入 git,见本地 `.env.remote`(已 git-ignored)。

| 项 | 值 |
|---|---|
| SSH | `root@192.168.80.249`(免密已配) |
| 密码 | 见本地 `.env.remote`(git-ignored) |
| 工作目录 | `/home/myFW` |
| 宿主机 Go | go1.25.0 |
| Docker | 24.0.2;编排用 `docker-compose`(带连字符,**无** `docker compose` 子命令) |

**与上文 debug 方案的关键差异**(实际环境以本节为准):
- **gitee 不可达**:本地与远程均无法解析 `gitee.com`,`git pull/push` 不可行。代码同步走「本地打包 scp 上传」(见下)。
- **部署形态**:实际用 `docker-compose.yml` + `deploy/docker/Dockerfile.compose`(容器内 `go build -mod=vendor` 编译后端并打入镜像,**非**挂载宿主机二进制),配置 `configs/controller-container.yaml`。
- **Agent**:`go build -o dist/myfw-agent ./cmd/agent` 后,`nohup ./dist/myfw-agent --config agent.yaml > agent.log 2>&1 &` 后台运行;证书/身份在 `/home/myFW`(`agent.yaml` 配 `data_dir: /home/myFW`)。

### 打包替换升级(因 gitee 不通,替代 git pull)

```bash
# 本地(Windows git bash,项目根):
go mod vendor                          # 填充 vendor/(Dockerfile -mod=vendor 必需)
( cd web && npm run build )            # 前端 dist
tar czf /tmp/myfw-src.tar.gz \
  --exclude='./.git' --exclude='node_modules' --exclude='web/dist' \
  --exclude='./dist' --exclude='./dev-ca' --exclude='./data' \
  --exclude='*.db' --exclude='*.log' --exclude='*.pem' --exclude='*.crt' --exclude='*.key' \
  --exclude='./.vscode' --exclude='./deploy-package' --exclude='dev-agent.yaml' \
  --exclude='*.tar.gz' .
( cd web && tar czf /tmp/myfw-dist.tar.gz dist )
scp /tmp/myfw-src.tar.gz /tmp/myfw-dist.tar.gz root@192.168.80.249:/tmp/

# 远程(root@192.168.80.249):
pkill -x myfw-agent                    # 停 Agent(必须 -x 精确匹配;`-f` 会命中自身命令行自杀)
cd /home/myFW && docker-compose down   # 停容器(带连字符)
rm -rf /home/myFW.old && mv /home/myFW /home/myFW.old          # 备份旧目录
mkdir -p /home/myFW && tar xzf /tmp/myfw-src.tar.gz -C /home/myFW
for f in node.id salt agent.yaml agent.crt agent.key dev-ca data; do
  [[ -e /home/myFW.old/$f ]] && cp -a /home/myFW.old/$f /home/myFW/
done                                   # 恢复运行时数据(节点身份/CA/DB)
tar xzf /tmp/myfw-dist.tar.gz -C /home/myFW/web/               # 前端 dist
docker-compose up -d --build           # 重建镜像+启动(容器内 go build)
CGO_ENABLED=0 go build -mod=vendor -o dist/myfw-agent ./cmd/agent   # 编译 Agent
```

### Agent 重新接入(Controller 数据库为空时)

远程 `data/` 为空时 Controller 不认识旧证书,Agent 需重新 bootstrap:
```bash
# 1. 拿一次性 bootstrap token
curl -X POST http://127.0.0.1:8080/api/v1/nodes/bootstrap -H "Content-Type: application/json" -d '{"note":"rebind"}'
# 2. 把 token 写入 agent.yaml 的 controller.bootstrap_token,并删旧证书(mv agent.crt agent.crt.bak)
# 3. 启动 Agent -> "bootstrap complete" status=PENDING
nohup ./dist/myfw-agent --config agent.yaml > agent.log 2>&1 &
# 4. approve -> ACTIVE
curl -X POST http://127.0.0.1:8080/api/v1/nodes/<node_id>/approve
```

---

## 1. 部署拓扑(单台远程 Linux)

```
远程 Linux  ~/go-iptablesops/
├─ Controller:Docker 容器 myfw-controller
│    端口映射:8080(Web)/ 9090(gRPC) → 宿主机
│    挂载:
│      dist/myfw-controller  → /usr/local/bin/myfw-controller(后端二进制)
│      web/dist              → /var/www/myfw(前端)
│      dev-ca                → /etc/myfw/ca(CA + 服务端证书)
│      data                  → /var/lib/myfw(SQLite)
│      configs/controller-debug.yaml → /etc/myfw/config.yaml
│
├─ Agent:工作目录 go build → sudo ./dist/myfw-agent 前台跑
│    连 127.0.0.1:9090(宿主机映射口)→ Controller 容器 gRPC
│
└─ 浏览器(本地 Windows):http://<远程IP>:8080  访问 Controller Web

本地 Windows:编辑代码 + git;前端本地 build 后上传 web/dist;大版本升级经确认后 push,远程 pull。
```

**端口**:8080(Web,浏览器)、9090(gRPC mTLS,Agent)。Agent 不监听端口,只出向连 Controller。
**同机联调零配置**:`make gen-ca` 默认 server 证书 SAN 含 `127.0.0.1`/`localhost`,Agent 连 `127.0.0.1:9090` 直通。

---

## 2. 前置准备

### 2.1 远程 Linux(一次性)

```bash
# Go 1.25+(编译后端二进制与 Agent)
wget -qO- https://go.dev/dl/go1.25.0.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc

# Docker(运行 Controller 容器)
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker

# Delve(可选,断点调试)
go install github.com/go-delve/delve/cmd/dlv@latest
```

> 远程**不需要** Node/npm——前端在本地构建后上传。

### 2.2 本地 Windows(一次性)

```bash
# Node 20(构建前端):https://nodejs.org/
node -v

# 首次安装前端依赖
cd web && npm install && cd ..
```

---

## 3. 首次部署

```bash
cd ~ && git clone https://gitee.com/wei-yilian/iptables-ops.git go-iptablesops
cd go-iptablesops

# 3.1 生成开发 CA(dev-ca/,git-ignored,远程持有)
make gen-ca

# 3.2 编译 Controller 二进制(静态,容器 alpine 可跑)
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/myfw-controller ./cmd/controller

# 3.3 前端:本地 Windows 构建并上传(远程无 Node)
#   本地执行(脚本自动 npm run build + 产物校验 + scp 上传 web/dist):
#     REMOTE=user@<远程IP> ./scripts/upload-frontend.sh
#   已 build 过想只上传:
#     SKIP_BUILD=1 REMOTE=user@<远程IP> ./scripts/upload-frontend.sh

# 3.4 构建运行时镜像 + 启动容器
mkdir -p data
docker compose -f docker-compose.debug.yml up -d --build

# 3.5 看日志确认就绪
docker logs -f myfw-controller
# 出现 "Web listening :8080" 与 "gRPC listening :9090" 即成功
```

浏览器访问 `http://<远程IP>:8080`,安全组放行 `8080/tcp`。

> ⚠️ 顺序很重要:`dist/myfw-controller` 必须在 `docker compose up` **之前**编译好;否则 Docker 会把挂载源当成目录创建,容器启动报 "not a directory"。

---

## 4. Agent 接入(同机)

```bash
# 4.1 编译 Agent
go build -o dist/myfw-agent ./cmd/agent

# 4.2 在 Web「新增待接入节点」拿到 bootstrap_token,写最小配置
cat >dev-agent.yaml <<EOF
controller:
  endpoint: 127.0.0.1:9090      # 宿主机映射口 → Controller 容器
  tls:
    ca_file: ./dev-ca/ca.pem
    cert_file: ./dev-agent.crt
    key_file: ./dev-agent.key
  bootstrap_token: "<Web 上拿到的 token>"
node:
  labels: [debug]
EOF
chmod 0600 dev-agent.yaml

# 4.3 前台运行(需 root 操作 Netfilter,日志直出)
sudo ./dist/myfw-agent --config dev-agent.yaml
```

回到 Web 对 PENDING 节点点「接入」→ ACTIVE,即可下发规则。

验证规则真实生效:`sudo iptables -S | grep MYFW`。

---

## 5. 日常迭代(后端/Agent 在远程,前端在本地)

> 远程跑的是「阶段性同步过去的版本」。本地改动需经第 6 节流程同步到远程后,才在这里生效。

### 5.1 后端 Go 改动(秒级,不重建镜像)

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/myfw-controller ./cmd/controller
docker restart myfw-controller
docker logs -f myfw-controller
```

### 5.2 前端改动(本地构建 + 上传,无需重启容器)

```bash
# 本地 Windows 执行(一条命令完成构建+校验+上传):
REMOTE=user@<远程IP> ./scripts/upload-frontend.sh
# 浏览器 Ctrl+F5 强刷(Controller 挂载的 dist 已更新)
```

`upload-frontend.sh` 环境变量:

| 变量 | 必填 | 说明 |
|---|---|---|
| `REMOTE` | 是 | SSH 目标,如 `user@10.0.0.10` |
| `DEST` | 否 | 远程项目目录,默认 `~/go-iptablesops` |
| `SKIP_BUILD` | 否 | `=1` 跳过本地构建,仅上传已有 `web/dist` |

> 也可手动:`cd web && npm run build` 后 `scp -r web/dist user@<远程IP>:~/go-iptablesops/web/`。

### 5.3 Agent 改动

```bash
# 在 Agent 终端 Ctrl-C 停旧进程,然后:
go build -o dist/myfw-agent ./cmd/agent
sudo ./dist/myfw-agent --config dev-agent.yaml
```

---

## 6. 代码同步策略

```
本地 Windows                          远程 Linux
─────────────                         ─────────────
编辑代码                              (跑阶段性版本,联调测试)
git commit(可多次)
   ↓ 攒到大版本 / 核心功能升级
与用户确认  ──────────────────►  确认后 push gitee
                                      git pull
                                      后端 go build + docker restart
                                      Agent go build + 重跑

前端改动(任意时机,不必等大版本同步):
  本地 upload-frontend.sh ──────────►  web/dist 更新,浏览器刷新
```

- **本地**做:代码编辑 + `git commit`;前端 `npm run build` + 上传(前端改动可随时上传,不必等大版本同步)。
- **同步时机**:大版本更迭或核心功能升级时,与用户确认后再 `git push`(代码同步);前端产物走 upload,不入 git。
- **远程**:`git pull` 后重新编译后端/Agent;前端靠本地 upload 更新。
- 远程产物(`dev-ca/`、`data/`、`dist/`、`web/dist`、`dev-agent.yaml`)均 git-ignored,只存远程。

---

## 7. 断点调试(Delve,可选)

实时改代码用第 5 节即可;需要断点/单步时用 Delve,**停掉容器**改在宿主机跑(共享同一份 `data/dev.db`):

```bash
# 7.1 后端断点(停容器,释放 8080/9090)
docker compose -f docker-compose.debug.yml stop
MYFW_DB_DRIVER=sqlite MYFW_DB_DSN=./data/dev.db \
dlv debug ./cmd/controller --headless --listen=0.0.0.0:2345 --api-version=2 --log \
  -- --config configs/controller.dev.yaml
# controller.dev.yaml 的 CA 路径(./dev-ca)在宿主机上;DSN 由 env 覆盖到 ./data/dev.db,与容器同库

# 7.2 Agent 断点(需 root + 真实 iptables)
sudo $HOME/go/bin/dlv debug ./cmd/agent --headless --listen=0.0.0.0:2346 --api-version=2 --log \
  -- --config dev-agent.yaml
```

本地 VSCode `.vscode/launch.json`(JSONC,改 `host`/`remotePath`,`.vscode/` 已 git-ignored):

```json
{
  "version": "0.2.0",
  "configurations": [
    {"name": "Attach Controller", "type": "go", "request": "attach", "mode": "remote",
     "host": "REMOTE_HOST", "port": 2345, "remotePath": "/home/USER/go-iptablesops"},
    {"name": "Attach Agent", "type": "go", "request": "attach", "mode": "remote",
     "host": "REMOTE_HOST", "port": 2346, "remotePath": "/home/USER/go-iptablesops"}
  ]
}
```

调试完恢复容器:`docker compose -f docker-compose.debug.yml start`。
安全组放行 `2345/2346` 仅调试期,勿长期暴露。

---

## 8. 排错清单

| 现象 | 根因 | 处理 |
|---|---|---|
| 容器启动报 "not a directory" | `dist/myfw-controller` 挂载前不存在,被建成目录 | 先 `go build -o dist/myfw-controller ./cmd/controller`,删掉误建的目录再 `up` |
| Agent mTLS 握手失败 | server 证书 SAN 不含 `127.0.0.1` | `make gen-ca` 默认含;若改过 SAN 需 `rm -rf dev-ca` 重生成 |
| 前端改了没生效 | 浏览器缓存 / 未上传 `web/dist` | 本地 `upload-frontend.sh` 重新上传 + 浏览器 `Ctrl+F5` |
| 脚本报"缺少 web/node_modules" | 未安装前端依赖 | `cd web && npm install` 后重跑 `upload-frontend.sh` |
| 脚本报"构建产物缺失" | `vite build` 失败 | 单独 `cd web && npm run build` 看报错,修复后再上传 |
| 8080/9090 起不来 | 端口被占 | `ss -lntp \| grep -E '8080\|9090'`;`docker ps` 看是否有残留容器 |
| Agent 显示「后端不可用」 | 无 iptables 或非 root | `sudo` 运行;确认主机有 iptables/nftables |
| `docker restart` 后旧逻辑仍在 | 二进制没重新编译 | 先 `go build` 再 `docker restart` |

---

## 9. 文件清单

| 文件 | 作用 | 入 git |
|---|---|---|
| `docs/remote-debug.md` | 本文档 | 是 |
| `docker-compose.debug.yml` | 调试 compose(挂载二进制/dist/CA/DB) | 是 |
| `deploy/docker/Dockerfile.debug` | 调试运行时镜像(alpine) | 是 |
| `configs/controller-debug.yaml` | 容器内 Controller 配置(容器路径) | 是 |
| `scripts/upload-frontend.sh` | 本地构建前端并上传远程(本地运行) | 是 |
| `dev-ca/` | 开发 CA | 否(git-ignored) |
| `data/` | SQLite 数据 | 否 |
| `dist/` | 后端/Agent 编译产物(远程) | 否 |
| `web/dist` | 前端构建产物(本地 build 后上传远程) | 否 |
| `dev-agent.yaml` | Agent 联调配置(含 token) | 否 |
