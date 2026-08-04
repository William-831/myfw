# 远程调试部署方案

## 实际联调环境

- 远程：`192.168.80.249`，目录 `/home/myFW`
- Controller：Docker（host 编译挂载），:8080 Web / :9090 gRPC
- Agent：systemd，同机接入

## 打包替换升级流程（核心）

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

## Agent 重新接入

Controller 数据库为空时，Agent 需重新 bootstrap：

1. Web「新增节点」拿一次性 bootstrap token
2. Agent 配置填 token，删旧证书（`mv agent.crt agent.crt.bak`）
3. 启动 Agent -> bootstrap complete，status=PENDING
4. Web approve -> ACTIVE

Agent 由 systemd 管理：`systemctl restart myfw-agent`，日志 `journalctl -u myfw-agent -f`。

## 部署拓扑（单台远程 Linux）

```
[Controller:Docker] :8080 Web / :9090 gRPC
       |
   [Agent:systemd]（同机接入）
       |
   iptables MYFW 链
```

挂载：dev-ca(CA) / data(SQLite) / configs/controller-container.yaml / web/dist / dist/myfw-controller。
