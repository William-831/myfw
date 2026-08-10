# 模板库导入导出 + 自动建库 设计文档

> 关联：`docs/design.md` § 2（数据持久化层）、§ 5（策略模型）。
> 本文档覆盖三块增量：① 外接 MySQL/OceanBase 自动建库（开箱即用）；② 模板库导入导出（迁移/备份/初始化）；③ 存量 iptables 脚本（YZINFO_RULES）分析生成模板文件。

## 1. 背景与目标

- **生产外接库开箱即用**：当前 `mysql.Open(DSN)` 在目标库不存在时直接报 `Unknown database`，需 DBA 预先 `CREATE DATABASE`。增量目标：程序启动自动建库，真正开箱即用。
- **模板库可迁移**：Mark / CustomChain / PolicyTemplate 落数据库，需支持导出为文件、从文件导入，用于环境迁移、定期备份、初始化装载。
- **存量脚本沉淀**：将运维既有 iptables 脚本（YZINFO_RULES）分析为平台模板文件，部署后手动导入，不硬编码到启动种子。

## 2. 模块一：自动建库

### 2.1 现状

- `cmd/controller/main.go:51-57`：启动调 `db.OpenFromEnv()` + `db.Migrate()`。
- `internal/db/db.go:108` `Migrate()` 调 `AutoMigrate(AllModels()...)` 自动建表/加列，幂等。
- 库本身不会自动创建：`gorm.io/driver/mysql` 的 `mysql.Open(DSN)` 连接时库名不存在即报错。

### 2.2 设计

- `internal/db/db.go` 新增 `ensureMySQLDatabase(cfg Config) error`，在 `Open()` 入口、`gorm.Open` 之前调用。
- 触发条件：`cfg.Driver == mysql` 且 `MYFW_DB_AUTOCREATE != "false"`（默认开启）。
- 流程：
  1. `github.com/go-sql-driver/mysql` 的 `mysql.ParseDSN(cfg.DSN)` 解析 DSN，提取 `DBName`、`Addr`、`User`、`Passwd`。
  2. 构造无库名 DSN（`DBName=""`），`sql.Open` 连接，`ping` 验通。
  3. `CREATE DATABASE IF NOT EXISTS \`<db>\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`。
  4. 关闭临时连接，返回；后续 `gorm.Open` 走原逻辑。
- SQLite 不处理（文件库自动创建）。

### 2.3 配置

| 环境变量 | 默认 | 说明 |
|---------|------|------|
| `MYFW_DB_AUTOCREATE` | `true` | mysql 时是否自动建库；DBA 严格环境可设 `false` 关闭 |

### 2.4 权限前提

DB 用户需 `CREATE` 权限。`deploy/docker/.env.example` 与 `docs/deployment.md` 标注。

### 2.5 TDD

- 红：`TestParseDSNExtractsDBName`（DSN 解析正确性）、`TestEnsureMySQLDatabaseNoOpOnSQLite`（sqlite 跳过）、`TestEnsureMySQLDatabaseDisabledByEnv`（开关关闭跳过）。
- 绿：实现 `ensureMySQLDatabase` + DSN 解析辅助。
- 集成验证：远程 192.168.80.249 实测 MySQL/OB 建库（或本地 MySQL 容器）。

## 3. 模块二：模板库导入导出

### 3.1 Bundle 格式（JSON）

```json
{
  "version": "1.0",
  "exported_at": "2026-08-06T12:00:00Z",
  "marks": [{"name":"ops","value":15,"description":"运维流量标记"}, ...],
  "custom_chains": [{"name":"business-input","parent":"MYFW-INPUT","table":"filter", ...}, ...],
  "templates": [
    {"name":"ops-mark-input-62022","group_name":"business-input","action":"MARK","mark":15,"protocol":"tcp","port_range":"62022", ...}
  ]
}
```

### 3.2 引用处理（关键）

数据库内外键用 ID，导出文件用 name 引用，保证跨环境可移植：

| 字段 | 数据库 | 导出文件 | 转换 |
|------|--------|---------|------|
| `PolicyTemplate.GroupID` | uint（CustomChain.ID） | `group_name` string | 导出查 CustomChain.Name；导入按 name 查 ID |
| `Mark` / `MatchMark` | uint32 数值 | 数值 | 不转换（模板存的是 Mark.Value，非 ID） |
| `SourceGroup` / `DestinationGroup` | string（地址组名） | string | 不转换（已是 name） |

### 3.3 导出 `Export(db) -> *Bundle`

- 全量查询 `Mark`、`CustomChain`、`PolicyTemplate`。
- PolicyTemplate 附 `group_name`：GroupID=0 时为空，否则查 CustomChain.Name。
- 不含节点实例（NodePolicyInstance 是节点绑定数据，不导出）。
- 不含 AddressGroup（第一版；source_group/destination_group 字段已是 name，引用缺失时导入后规则指向不存在的组名，UI 可见可修）。

### 3.4 导入 `Import(db, bundle, policy) -> *Result`

- **单事务**，失败整体回滚。
- **依赖顺序**：Mark -> CustomChain -> PolicyTemplate。
- **冲突策略**（按 `name` 判重，`Mark` 额外按 `value`）：

| 策略 | 行为 |
|------|------|
| `skip`（默认） | 已存在则跳过，计数 `skipped` |
| `overwrite` | 已存在则用文件值覆盖（保留 ID），计数 `overwritten` |
| `fail` | 遇冲突即报错回滚 |

- PolicyTemplate 导入时按 `group_name` 查 CustomChain.ID；查不到则该条记 `skipped`（组缺失）并在 Result 说明。
- Result：`{marks_created, marks_skipped, chains_created, chains_skipped, templates_created, templates_skipped, errors:[]}`。

### 3.5 API（挂 `template_routes.go`）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/templates/export` | 返回 Bundle JSON，`Content-Disposition` 触发下载 |
| POST | `/api/v1/templates/import` | body `{"policy":"skip","bundle":{...}}`，返回 ImportResult |

- 导入走审计（`audit.tpl import`）。
- 导出无需审计（只读）。

### 3.6 前端（`TemplateLibrary.vue` + `api/index.js`）

- 模板库页加「导出」「导入」按钮。
- 导出：`GET /export` -> `Blob` -> 触发文件下载 `templates-YYYYMMDD.json`。
- 导入：弹窗选文件 + 冲突策略下拉（skip/overwrite/fail）-> `POST /import` -> 显示 Result 摘要 -> 刷新列表。

### 3.7 TDD

- 红：`TestExportBundleContainsAll`、`TestExportTemplateNameResolved`。
- 红：`TestImportSkipExisting`、`TestImportOverwriteExisting`、`TestImportFailOnConflict`、`TestImportTransactionRollback`、`TestImportResolvesGroupByName`。
- 绿：实现 `Export` / `Import`。
- 红：`TestExportAPI`、`TestImportAPI`。
- 绿：挂路由。
- 前端联调。

## 4. 模块三：YZINFO 模板

### 4.1 脚本语义分析

```
rule_name="YZINFO_RULES"   ops_mark=15   dev_mark=255
create_default: -N YZINFO_RULES; -A RETURN; 建 ops/dev 规则; -I INPUT/FORWARD/DOCKER-USER -j YZINFO_RULES
reset: -F YZINFO_RULES; -A RETURN; 重建
help 子命令: mark-input/unmark-input ops|dev 62022 8080
            mark-mangle/unmark-mangle ops|dev 62022 8080
```

提取：

| 脚本元素 | 平台映射 |
|---------|---------|
| `ops_mark=15` / `dev_mark=255` | `Mark` name=ops/dev，value=15/255 |
| `YZINFO_RULES` 挂 INPUT | `PolicyTemplate` 归 `business-input` 组（内置，Parent=MYFW-INPUT） |
| `YZINFO_RULES` 挂 FORWARD/DOCKER-USER | 归 `acl-forward` 组（内置，容器转发），不扩展 DOCKER-USER |
| `mark-input ops/dev 62022 8080` | filter 表 INPUT 打标，4 条模板 |
| `mark-mangle ops/dev 62022 8080` | mangle 表打标，归 `mark-mangle` 组，4 条模板 |

### 4.2 模板内容（`deploy/templates/yzinfo-rules.json`）

- 2 Mark：`{ops,15,"运维流量标记"}`、`{dev,255,"开发流量标记"}`。
- 0 CustomChain（复用内置 business-input / acl-forward / mark-mangle，不新建）。
- 8 PolicyTemplate：
  - business-input 组 4 条：ops-62022、ops-8080、dev-62022、dev-8080（action=MARK，protocol=tcp）
  - mark-mangle 组 4 条：同上端口/角色，归 mark-mangle
- FORWARD 部分：acl-forward 组暂不放打标模板（脚本 FORWARD 挂链仅为框架预留，无实际 mark 规则），如需可后续补。

### 4.3 使用方式

部署后：Web 模板库页「导入」-> 选 `yzinfo-rules.json` -> 策略 skip -> 导入。8 模板 + 2 Mark 落库，可在节点策略实例化下发。

## 5. 文件清单

| 文件 | 动作 | 内容 |
|------|------|------|
| `internal/db/db.go` | 改 | `ensureMySQLDatabase` + `Open` 前置调用 |
| `internal/db/db_mysql_test.go` | 改 | DSN 解析、开关、跳过测试 |
| `internal/controller/templateio/templateio.go` | 新 | `Bundle` / `Export` / `Import` |
| `internal/controller/templateio/templateio_test.go` | 新 | 导出导入全场景测试 |
| `internal/controller/server/template_routes.go` | 改 | 加 export/import 路由 |
| `internal/controller/server/template_routes_test.go` | 新/改 | API 测试 |
| `web/src/views/TemplateLibrary.vue` | 改 | 导出/导入按钮 + 弹窗 |
| `web/src/api/index.js` | 改 | exportTemplates / importTemplates |
| `deploy/templates/yzinfo-rules.json` | 新 | YZINFO 模板 |
| `deploy/docker/.env.example` | 改 | 标注 MYFW_DB_AUTOCREATE |
| `docs/code-analysis.md` | 改 | 同步 templateio 包 |

## 6. 实施顺序

1. 模块一 自动建库（TDD）-> 远程验证
2. 模块二 导入导出核心（TDD）-> API（TDD）-> 前端
3. 模块三 生成 YZINFO JSON -> 导入验证
4. 同步 `docs/code-analysis.md`，远程端到端验证，提交 Gitee
