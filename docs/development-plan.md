# 开发方案

## 1. 总体原则

- 本地仅编辑 + git push，编译/测试/打包在远程 Linux 执行
- 仓库只保留源代码，构建产物/缓存/本地配置 gitignore
- 中文注释，简体中文沟通，Commit Message 中文

## 2. 项目目录结构

```
iptables-tool/
├── api/myfw/v1/         # proto 生成的 Go/gRPC 代码
├── cmd/{controller,agent}/  # 入口
├── configs/             # 配置(dev/container/debug/prod.example)
├── deploy/
│   ├── docker/          # Dockerfile.compose/debug + .env.example
│   └── systemd/         # Agent systemd unit + 安装脚本
├── docs/                # 功能说明/开发方案/远程部署调试文档
├── internal/
│   ├── agent/           # bootstrap/capability/conn/driver/handler/watchdog
│   ├── controller/      # compiler/policy/server/task/stream/audit/auth/pki
│   ├── db/              # GORM 迁移
│   ├── model/           # 数据模型
│   ├── pki/             # 证书签发
│   └── security/        # mTLS/HMAC/会话
├── proto/myfw/v1/       # protobuf 定义
├── scripts/             # 构建/部署/CA/proto 脚本
├── web/src/             # Vue3 前端
├── docker-compose.yml   # Controller 部署(host 编译挂载)
├── go.mod / go.sum
├── Makefile
└── buf.yaml / buf.gen.yaml  # proto 生成配置
```

## 3. 里程碑概览

M0-M12 全部完成，核心功能已落地：

| 里程碑 | 完成内容 | 状态 |
|---|---|---|
| M0 | 项目脚手架、配置、Dockerfile、systemd unit | ✅ |
| M1 | Proto 契约 + GORM 模型 + AutoMigrate | ✅ |
| M2 | Controller(Gin Web + gRPC + 流式注册) | ✅ |
| M3 | PKI 自签 CA + Agent bootstrap + mTLS | ✅ |
| M4 | Agent 骨架 + 能力探测 + 重新注册 | ✅ |
| M5 | IptablesDriver(MYFW 命名空间 + 期望态同步 + 孤儿链清理) | ✅ |
| M6 | 两级策略模型(Template+Instance) + Rule Compiler + MARK 白名单 | ✅ |
| M7 | Coordinator 状态机 + 审批 + 快照回滚 + 保护期 | ✅ |
| M8 | Watchdog drift 检测 + jump 顺序修复 | ✅ |
| M9 | NftablesDriver(backend 切换) | ✅ |
| M10 | 节点状态采集 + Dashboard | ✅ |
| M11 | Vue3 前端(节点策略/模板库/保护期/审计/系统设置) | ✅ |
| M12 | 审计日志聚合 + 保留清理 + 告警预留 | ✅ |

## 4. Git 工作流

- 主分支 master，直接提交推送 Gitee
- Commit Message 中文，简明描述变更
- 提交前检查 .gitignore，不提交构建产物/缓存/本地配置

## 5. 后续待办

- 回滚后实例 applied/enabled 同步（drift 重同步兜底）
- 打包分发（M13）
