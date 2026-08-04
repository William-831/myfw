# iptables-tool

Linux 服务器统一网络防火墙管理平台。Controller 集中管理多节点 iptables，Agent 落地执行，规则收敛在 `MYFW` 命名空间（不动 DOCKER/KUBE/用户手工规则）。

## 核心特性

- **两级策略模型**：PolicyTemplate（模板库）+ NodePolicyInstance（节点实例，独立参数快照）
- **MARK 白名单**：方向+源+端口+标记，自动生成打标+放行+兜底DROP 三条联动规则
- **保护期回滚**：下发后 5 分钟确认窗口，超时自动回滚快照，误操作可恢复
- **多节点管理**：节点级 dispatch、drift 漂移检测、地址组(ipset)、自定义链
- **安全通信**：Agent 主动连 Controller，mTLS + HMAC 防重放 + IP 钉扎 + 证书轮换

## 技术栈

Go（Gin + gRPC + GORM）+ Vue 3（Element Plus）+ SQLite(dev)/MySQL(prod)

## 快速开始

```bash
# 开发环境（SQLite）
make dev-controller

# 编译 Agent（静态链接，Linux）
make build-agent-linux

# Docker 部署 Controller（host 编译挂载）
docker-compose up -d
```

## 文档

| 文档 | 内容 |
|---|---|
| [design.md](./docs/design.md) | 架构、模型、MYFW 链结构、状态机 |
| [deployment.md](./docs/deployment.md) | Controller/Agent 部署运维 |
| [remote-debug.md](./docs/remote-debug.md) | 远程联调方案 |
| [mark-acl-docker.md](./docs/mark-acl-docker.md) | MARK 白名单拦截设计 |
| [development-plan.md](./docs/development-plan.md) | 开发方案与里程碑 |
| [progress.md](./docs/progress.md) | 开发进度 |
