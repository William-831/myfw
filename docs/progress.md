# 开发进度

## 里程碑完成情况

M0-M12 全部完成，核心功能已落地：

| 里程碑 | 完成内容 |
|---|---|
| M0 | 项目脚手架、配置、Dockerfile、systemd unit |
| M1 | Proto 契约 + GORM 模型 + AutoMigrate |
| M2 | Controller(Gin Web + gRPC + 流式注册) |
| M3 | PKI 自签 CA + Agent bootstrap + mTLS |
| M4 | Agent 骨架 + 能力探测 + 重新注册 |
| M5 | IptablesDriver(MYFW 命名空间 + 期望态同步 + 孤儿链清理) |
| M6 | 两级策略模型(Template+Instance) + Rule Compiler + MARK 白名单 |
| M7 | Coordinator 状态机 + 审批 + 快照回滚 + 保护期 |
| M8 | Watchdog drift 检测 + jump 顺序修复 |
| M9 | NftablesDriver(backend 切换) |
| M10 | 节点状态采集 + Dashboard |
| M11 | Vue3 前端(节点策略/模板库/保护期/审计/系统设置) |
| M12 | 审计日志聚合 + 保留清理 + 告警预留 |

## 后续待办

- 回滚后实例 applied/enabled 同步（drift 重同步兜底）
- 打包分发（M13）
