# 远程调试部署方案

> 用途:在远程 Linux 上部署 Controller(Docker 容器)+ Agent(工作目录编译)进行功能联调。
> 本地 Windows **仅编辑代码与 git**,不做任何编译/部署。
> 配套文件:`deploy/docker/Dockerfile.debug`、`docker-compose.debug.yml`、`configs/controller-debug.yaml`。
>
> 部署形态约定:
> - **Controller**:Docker 容器(alpine 运行时),二进制/前端/CA/DB 全部挂载宿主机产物。
> - **前端**:宿主机 `npm run build` 产物 `web/dist` 挂载进容器,与镜像解耦(持久化)。
> - **Agent**:远程工作目录 `go build`,前台 `sudo` 运行,不用 systemd。
> - **数据库**:SQLite(挂载持久化),不接 OceanBase。
> - **同步**:本地攒改动 → 大版本/核心功能升级 → 经确认 → push gitee → 远程 pull。

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

本地 Windows:编辑代码 + git;大版本升级经确认后 push,远程 pull。
```

**端口**:8080(Web,浏览器)、9090(gRPC mTLS,Agent)。Agent 不监听端口,只出向连 Controller。
**同机联调零配置**:`make gen-ca` 默认 server 证书 SAN 含 `127.0.0.1`/`localhost`,Agent 连 `127.0.0.1:9090` 直通。

---

## 2. 前置准备(远程,一次性)

```bash
# Go 1.25+
wget -qO- https://go.dev/dl/go1.25.0.linux-amd64.tar.gz | sudo tar -C /usr/local -xz
echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc

# Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker

# Node 20(构建前端)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt install -y nodejs

# Delve(可选,断点调试)
go install github.com/go-delve/delve/cmd/dlv@latest
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

# 3.3 构建前端(产物落 web/dist)
cd web && npm install && npm run build && cd ..

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

## 5. 日常迭代(三端更新,远程执行)

> 远程跑的是「阶段性同步过去的版本」。本地改动需经第 6 节流程同步到远程后,才在这里生效。

### 5.1 后端 Go 改动(秒级,不重建镜像)

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/myfw-controller ./cmd/controller
docker restart myfw-controller
docker logs -f myfw-controller
```

### 5.2 前端改动(无需重启容器)

```bash
cd web && npm run build && cd ..
# 浏览器 Ctrl+F5 强刷(Controller serve 的 dist 已更新)
```

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
                                      按第 5 节重新编译/构建/重启
```

- **本地**只做:代码编辑 + `git commit`(可多次小提交)。
- **同步时机**:大版本更迭或核心功能升级时,与用户确认后再 `git push`。
- **远程**:`git pull` 后按第 5 节让三端更新生效。
- 远程产物(`dev-ca/`、`data/`、`dist/`、`dev-agent.yaml`)均 git-ignored,只存远程。

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
| 前端改了没生效 | 浏览器缓存 / `web/dist` 未 rebuild | `npm run build` + 浏览器 `Ctrl+F5` |
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
| `dev-ca/` | 开发 CA | 否(git-ignored) |
| `data/` | SQLite 数据 | 否 |
| `dist/` | 编译产物 | 否 |
| `dev-agent.yaml` | Agent 联调配置(含 token) | 否 |
