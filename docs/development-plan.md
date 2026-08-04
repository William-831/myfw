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
├── docs/                # 设计/部署/调试文档
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

| 里程碑 | 内容 | 状态 |
|---|---|---|
| M0 | 项目脚手架 | ✅ |
| M1 | 契约层(Proto + DB Schema) | ✅ |
| M2 | Controller 骨架(Gin+gRPC) | ✅ |
| M3 | PKI + 节点注册(mTLS) | ✅ |
| M4 | Agent 骨架 + 能力探测 | ✅ |
| M5 | Firewall Driver + IptablesDriver | ✅ |
| M6 | 策略模型 + Rule Compiler | ✅ |
| M7 | 变更审批 + 快照 + 自动回滚 | ✅ |
| M8 | Watchdog 漂移检测 | ✅ |
| M9 | NftablesDriver | ✅ |
| M10 | 状态采集 | ✅ |
| M11 | Web 前端 | ✅ |
| M12 | 审计/观测完善 | ✅ |

## 4. Git 工作流

- 主分支 master，直接提交推送 Gitee
- Commit Message 中文，简明描述变更
- 提交前检查 .gitignore，不提交构建产物/缓存/本地配置
