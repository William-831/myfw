# iptables-tool

面向 Linux 服务器环境的统一网络防火墙管理平台。

- **Controller**：Docker 部署的 Web 主控（Gin + gRPC + GORM）。
- **Agent**：裸机 systemd 部署的被控二进制（无 Docker、无 CGO、静态编译）。
- **数据库**：生产接现成的 OceanBase（MySQL 协议兼容，通过环境变量注入），开发用 SQLite。
- **通信**：Agent 主动连 Controller，强制 mTLS。
- **规则隔离**：所有平台规则收敛在 `MYFW` 命名空间，不动 DOCKER / KUBE / 用户手工规则。

## 文档

| 文档 | 内容 |
|---|---|
| [docs/design.md](./docs/design.md) | 架构、模型、原则、决策 |
| [docs/deployment.md](./docs/deployment.md) | Controller / Agent 部署与运维手册 |
| [docs/development-plan.md](./docs/development-plan.md) | 分阶段开发方案、目录结构、Git 工作流 |
| [docs/progress.md](./docs/progress.md) | 当前进度追踪 |

## 快速开始

**当前阶段**：M0 项目脚手架（详见 [progress.md](./docs/progress.md)）。

代码尚未开始落地，如需了解设计和后续计划请从上面的文档入手。
