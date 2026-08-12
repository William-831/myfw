package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gormlogger "gorm.io/gorm/logger"

	"iptables-tool/internal/db"
	"iptables-tool/internal/model"
)

// TestExportTemplatesAPI 验证 GET /api/v1/templates/export 返回 bundle JSON 且包含预置数据。
func TestExportTemplatesAPI(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 预置数据
	gdb.Create(&model.Mark{Name: "test-mark", Value: 99, Description: "test"})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/templates/export", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var body struct {
		Bundle any `json:"bundle"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	// 验证 bundle 包含 test-mark
	if !strings.Contains(w.Body.String(), "test-mark") {
		t.Fatalf("bundle should contain test-mark, body=%s", w.Body.String())
	}
}

// TestImportTemplatesAPI 验证 POST /api/v1/templates/import 导入 bundle 成功。
func TestImportTemplatesAPI(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"policy":"skip","bundle":{"version":"1.0","marks":[{"name":"test-import","value":88,"description":"test import"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}

	var result struct {
		MarksCreated int `json:"marks_created"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if result.MarksCreated != 1 {
		t.Fatalf("marks_created: got %d, want 1", result.MarksCreated)
	}
}

// TestCreateTemplateWithMissingGroupRejected 验证模板创建时 group_id 指向不存在的策略组
// 被 400 拒绝(漏洞 D 修复:模板不再绑定悬空组,避免实例化后到 dispatch 才报错)。
func TestCreateTemplateWithMissingGroupRejected(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"name":"bad-tpl","group_id":999,"action":"ACCEPT"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
}

// TestCreateTemplateWithExistingGroupOK 验证 group_id 存在时模板创建成功(回归)。
func TestCreateTemplateWithExistingGroupOK(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.CustomChain{ID: 5, Name: "grp", Parent: "MYFW-FORWARD", Table: "filter"})
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"name":"ok-tpl","group_id":5,"action":"ACCEPT"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// TestInstanceDriftSpecVersion 验证 drift 判据基于 SpecVersion(漏洞 A 修复):
//   - SpecVersion 相等不 drift,落后即 drift;
//   - 模板 SpecVersion=0(旧数据未用新版编辑)时回退时间戳判据,不丢存量 drift。
func TestInstanceDriftSpecVersion(t *testing.T) {
	inst := &model.NodePolicyInstance{SyncedSpecVersion: 1, SyncedTemplateUpdatedAt: time.Now()}
	// SpecVersion 相等:即使模板 UpdatedAt 更新(比如改了描述),也不 drift
	equalTpl := &model.PolicyTemplate{SpecVersion: 1, UpdatedAt: time.Now().Add(time.Hour)}
	if instanceDrift(inst, equalTpl) {
		t.Fatal("SpecVersion 相等时不应 drift(改描述等非规则字段不触发)")
	}
	// 模板规则字段更新:SpecVersion=2 > 1,应 drift
	newerTpl := &model.PolicyTemplate{SpecVersion: 2, UpdatedAt: time.Now().Add(time.Hour)}
	if !instanceDrift(inst, newerTpl) {
		t.Fatal("SpecVersion 落后时不应 drift")
	}
	// 旧数据兼容:模板 SpecVersion=0,回退时间戳判据
	legacyTpl := &model.PolicyTemplate{SpecVersion: 0, UpdatedAt: time.Now().Add(time.Hour)}
	if !instanceDrift(inst, legacyTpl) {
		t.Fatal("模板 SpecVersion=0 时应回退 UpdatedAt 判据")
	}
	legacyInst := &model.NodePolicyInstance{SyncedSpecVersion: 0, SyncedTemplateUpdatedAt: time.Now().Add(2 * time.Hour)}
	if instanceDrift(legacyInst, legacyTpl) {
		t.Fatal("模板 UpdatedAt 不晚于实例时旧判据也不应 drift")
	}
}

// TestSyncInstanceFullOverwrite 验证 sync 全量覆盖实例规则字段(漏洞 E 修复):
// 模板字段清空也能传播到实例,不再是"非空才覆盖"造成的假同步;
// 实例名/启用状态保留,applied 置 false 待下发,sync 版本快照更新。
func TestSyncInstanceFullOverwrite(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 模板:Source 已清空(之前有值,规则字段变化过,SpecVersion=2)
	gdb.Create(&model.PolicyTemplate{
		ID: 1, Name: "tpl", GroupID: 5, Source: "", Protocol: "TCP",
		Action: "ACCEPT", SpecVersion: 2,
	})
	// 实例:Source 保留旧值(节点特有,旧版 sync 不覆盖),SyncedSpecVersion=1(旧)
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", TemplateID: 1, Name: "inst",
		Source: "1.1.1.1", Protocol: "TCP", Action: "ACCEPT",
		Enabled: true, Applied: true, SyncedSpecVersion: 1,
	})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/instances/1/sync", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("查实例: %v", err)
	}
	if inst.Source != "" {
		t.Fatalf("sync 应全量覆盖,模板 Source 为空则实例 Source 应为空, got %q", inst.Source)
	}
	if inst.SyncedSpecVersion != 2 {
		t.Fatalf("sync 后 SyncedSpecVersion 应=模板 SpecVersion(2), got %d", inst.SyncedSpecVersion)
	}
	if inst.Applied {
		t.Fatal("sync 后 applied 应置 false 待下发")
	}
	if inst.Name != "inst" || !inst.Enabled {
		t.Fatal("sync 不应改实例名/启用状态")
	}
}

// TestCreateTemplateDuplicateNameRejected 验证模板重名创建被 409 拒绝。
// 模板 name 唯一后,import 按 name 去重才可靠(漏洞 K 修复)。
func TestCreateTemplateDuplicateNameRejected(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "dup-tpl"})
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"name":"dup-tpl","action":"ACCEPT"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409, body=%s", w.Code, w.Body.String())
	}
}

// TestUpdateTemplateRenameConflictRejected 验证模板改名与其他模板重名被 409 拒绝(漏洞 K 修复)。
func TestUpdateTemplateRenameConflictRejected(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "tpl-a"})
	gdb.Create(&model.PolicyTemplate{ID: 2, Name: "tpl-b"})
	h := BuildWebHandler(gdb, time.Minute)

	// 把 id=1 改名为 tpl-b,与 id=2 撞名
	body := `{"name":"tpl-b","action":"ACCEPT"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/templates/1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status: got %d, want 409, body=%s", w.Code, w.Body.String())
	}
}

// TestCreateTemplateMarkNotInMarkTableRejected 验证 MARK 模板的打标值未在标记管理
// 定义时被 400 拒绝(1.2 修复:校验引用标记管理,不再硬编码 15/255)。
// 标记语义(dev=开发/ops=运维等)由标记管理统一承载,未定义的值不可用于规则。
func TestCreateTemplateMarkNotInMarkTableRejected(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	h := BuildWebHandler(gdb, time.Minute)

	// MARK 白名单模板:mark=100 但标记管理未定义该值(Mark 表只有 dev/ops=15/255)
	gdb.Create(&model.Mark{Name: "dev", Value: 15, Description: "开发"})
	gdb.Create(&model.Mark{Name: "ops", Value: 255, Description: "运维"})
	body := `{"name":"mark-tpl","action":"MARK","mark":100,"protocol":"TCP","port_range":"8080","source":"10.0.0.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "标记管理") {
		t.Fatalf("error 应提示标记管理, body=%s", w.Body.String())
	}
}

// TestCreateTemplateMarkInMarkTableOK 验证标记管理已定义的标记值可正常用于 MARK 模板
// (回归:dev=15/ops=255 及任意已定义值均通过,非 15/255 硬编码)。
func TestCreateTemplateMarkInMarkTableOK(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.Mark{Name: "business", Value: 100, Description: "业务A"})
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"name":"mark-tpl","action":"MARK","mark":100,"protocol":"TCP","port_range":"8080","source":"10.0.0.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// TestGetNodeInstancesDriftFields 验证实例列表接口返回配置侧漂移字段级详情:
// drift(模板 SpecVersion 领先)+ deviated(实例参数与模板当前不一致)+ 字段级 diff,
// 用于前端"模板已更新(N字段)"角标与偏离提示(配置侧漂移治理 1.1)。
func TestGetNodeInstancesDriftFields(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 模板 SpecVersion=2,实例 SyncedSpecVersion=1(模板侧 drift)+ Source 被手动偏离
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "tpl", Source: "10.0.0.0/24", Action: "ACCEPT", SpecVersion: 2})
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", TemplateID: 1, Name: "inst",
		Source: "192.168.1.0/24", Action: "ACCEPT", Enabled: true,
		SyncedSpecVersion: 1,
	})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/n1/instances", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Instances []struct {
			Drift          bool     `json:"drift"`
			DriftFields    []string `json:"drift_fields"`
			Deviated       bool     `json:"deviated"`
			DeviatedFields []string `json:"deviated_fields"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if len(body.Instances) != 1 {
		t.Fatalf("应返回 1 个实例, got %d", len(body.Instances))
	}
	inst := body.Instances[0]
	if !inst.Drift {
		t.Fatal("模板 SpecVersion(2) > 实例(1),drift 应为 true")
	}
	if !inst.Deviated {
		t.Fatal("实例 Source 与模板当前不一致,deviated 应为 true")
	}
	if len(inst.DriftFields) != 1 || inst.DriftFields[0] != "source" {
		t.Fatalf("drift_fields 应含 [source], got %v", inst.DriftFields)
	}
	if len(inst.DeviatedFields) != 1 || inst.DeviatedFields[0] != "source" {
		t.Fatalf("deviated_fields 应含 [source], got %v", inst.DeviatedFields)
	}
}

// TestInstanceDiffFields 验证实例与模板参数级 diff(配置侧漂移治理):
// 返回不一致的规则字段名列表,用于 drift 详情展示与偏离检测。
// 字段集同 templateSpecChanged:规则字段;描述等非规则字段不参与。
func TestInstanceDiffFields(t *testing.T) {
	tpl := &model.PolicyTemplate{
		GroupID: 5, Direction: "", Source: "10.0.0.0/24", Destination: "",
		Protocol: "TCP", PortRange: "8080", Action: "ACCEPT", Mark: 0,
		NatTo: "", SourceGroup: "", DestinationGroup: "", MatchMark: 0, Priority: 10,
	}
	// 完全一致:空列表
	inst := &model.NodePolicyInstance{
		GroupID: 5, Direction: "", Source: "10.0.0.0/24", Destination: "",
		Protocol: "TCP", PortRange: "8080", Action: "ACCEPT", Mark: 0,
		NatTo: "", SourceGroup: "", DestinationGroup: "", MatchMark: 0, Priority: 10,
	}
	if fields := instanceDiffFields(inst, tpl); len(fields) != 0 {
		t.Fatalf("参数一致应返回空列表, got %v", fields)
	}
	// Source 偏离:仅返回 source
	inst.Source = "192.168.1.0/24"
	fields := instanceDiffFields(inst, tpl)
	if len(fields) != 1 || fields[0] != "source" {
		t.Fatalf("仅 Source 偏离应返回 [source], got %v", fields)
	}
	// 多字段偏离:source/port_range/priority
	inst.PortRange = "9090"
	inst.Priority = 20
	fields = instanceDiffFields(inst, tpl)
	if len(fields) != 3 {
		t.Fatalf("应有 3 字段偏离(source/port_range/priority), got %v", fields)
	}
	// 描述不同不算偏离(非规则字段)
	inst.Description = "手动改了描述"
	fields = instanceDiffFields(inst, tpl)
	if len(fields) != 3 {
		t.Fatalf("描述非规则字段不应计入,仍 3 字段, got %v", fields)
	}
}

// TestInstanceDeviated 验证实例手动偏离模板检测(不依赖 SpecVersion):
// 实例参数与模板当前参数不一致即为偏离,与 instanceDrift(模板侧 SpecVersion 判据)互补。
func TestInstanceDeviated(t *testing.T) {
	tpl := &model.PolicyTemplate{Source: "10.0.0.0/24", Action: "ACCEPT", SpecVersion: 1}
	// SyncedSpecVersion 与模板一致(不 drift),但参数偏离(手动改了 Source)
	inst := &model.NodePolicyInstance{
		Source: "192.168.1.0/24", Action: "ACCEPT", SyncedSpecVersion: 1,
	}
	if instanceDrift(inst, tpl) {
		t.Fatal("SpecVersion 相等不应 drift")
	}
	if !instanceDeviated(inst, tpl) {
		t.Fatal("参数不一致应判定为偏离")
	}
	// 参数一致:不偏离
	inst.Source = "10.0.0.0/24"
	if instanceDeviated(inst, tpl) {
		t.Fatal("参数一致不应偏离")
	}
}

// TestSyncInstancePreview 验证 sync 预览接口返回字段级 diff(当前 vs 模板最新)且不落库。
// 用于前端 sync 确认前展示"将覆盖哪些字段",降低手动同步认知负担(配置侧漂移治理 1.2)。
func TestSyncInstancePreview(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 模板 Source=10.0.0.0/24 + PortRange=8080;实例被手动改成 192.168.1.0/24 + 9090
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "tpl", Source: "10.0.0.0/24", PortRange: "8080", Action: "ACCEPT", SpecVersion: 2})
	gdb.Create(&model.NodePolicyInstance{
		ID: 1, NodeID: "n1", TemplateID: 1, Name: "inst",
		Source: "192.168.1.0/24", PortRange: "9090", Action: "ACCEPT", Enabled: true,
		SyncedSpecVersion: 1,
	})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/instances/1/sync-preview", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Fields []struct {
			Field    string `json:"field"`
			Current  string `json:"current"`
			Template string `json:"template"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if len(body.Fields) != 2 {
		t.Fatalf("应有 2 字段 diff(source/port_range), got %v", body.Fields)
	}
	byName := map[string]struct {
		Current  string
		Template string
	}{}
	for _, f := range body.Fields {
		byName[f.Field] = struct {
			Current  string
			Template string
		}{f.Current, f.Template}
	}
	if s, ok := byName["source"]; !ok || s.Current != "192.168.1.0/24" || s.Template != "10.0.0.0/24" {
		t.Fatalf("source diff 不符: got %+v", byName["source"])
	}
	if p, ok := byName["port_range"]; !ok || p.Current != "9090" || p.Template != "8080" {
		t.Fatalf("port_range diff 不符: got %+v", byName["port_range"])
	}
	// 预览不落库:实例 Source 仍为手动值
	var inst model.NodePolicyInstance
	if err := gdb.First(&inst, 1).Error; err != nil {
		t.Fatalf("查实例: %v", err)
	}
	if inst.Source != "192.168.1.0/24" {
		t.Fatal("sync-preview 不应修改实例参数")
	}
}

// TestSyncAllInstances 验证节点级批量同步只同步 drift 实例(配置侧漂移治理 1.3):
// 同步该节点所有模板 SpecVersion 领先的实例,已同步的跳过,不影响其他节点实例。
func TestSyncAllInstances(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "tpl-a", Source: "10.0.0.0/24", Action: "ACCEPT", SpecVersion: 2})
	gdb.Create(&model.PolicyTemplate{ID: 2, Name: "tpl-b", Source: "10.0.0.0/24", Action: "ACCEPT", SpecVersion: 2})
	// n1: inst1 drift(SyncedSpecVersion=1 < 2), inst2 已同步(2)
	gdb.Create(&model.NodePolicyInstance{ID: 1, NodeID: "n1", TemplateID: 1, Name: "i1", Source: "1.1.1.1", Action: "ACCEPT", Enabled: true, Applied: true, SyncedSpecVersion: 1})
	gdb.Create(&model.NodePolicyInstance{ID: 2, NodeID: "n1", TemplateID: 2, Name: "i2", Source: "10.0.0.0/24", Action: "ACCEPT", Enabled: true, Applied: true, SyncedSpecVersion: 2})
	// n2: inst3 drift,不应被 n1 的 sync-all 影响
	gdb.Create(&model.NodePolicyInstance{ID: 3, NodeID: "n2", TemplateID: 1, Name: "i3", Source: "1.1.1.1", Action: "ACCEPT", Enabled: true, SyncedSpecVersion: 1})
	h := BuildWebHandler(gdb, time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/sync-all", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200, body=%s", w.Code, w.Body.String())
	}
	var body struct {
		Synced  int `json:"synced"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if body.Synced != 1 || body.Skipped != 1 {
		t.Fatalf("synced/skipped 应为 1/1, got %d/%d", body.Synced, body.Skipped)
	}
	// n1 inst1 已同步:参数覆盖 + SyncedSpecVersion=2 + applied 置 false
	// (独立变量查 ID,避免复用结构体脏主键)
	var inst1 model.NodePolicyInstance
	if err := gdb.Where("id = ?", 1).First(&inst1).Error; err != nil {
		t.Fatalf("查实例1: %v", err)
	}
	if inst1.Source != "10.0.0.0/24" || inst1.SyncedSpecVersion != 2 || inst1.Applied {
		t.Fatalf("inst1 应同步为模板参数+spec=2+applied=false, got src=%q spec=%d applied=%v", inst1.Source, inst1.SyncedSpecVersion, inst1.Applied)
	}
	// n2 inst3 不受影响
	var inst3 model.NodePolicyInstance
	if err := gdb.Where("id = ?", 3).First(&inst3).Error; err != nil {
		t.Fatalf("查实例3: %v", err)
	}
	if inst3.Source != "1.1.1.1" || inst3.SyncedSpecVersion != 1 {
		t.Fatalf("inst3 不应被其他节点 sync-all 影响, got src=%q spec=%d", inst3.Source, inst3.SyncedSpecVersion)
	}
}

// TestCreateTemplateIgnoresClientID 验证创建模板时忽略前端传入的 id(问题 4 修复):
// 前端 form 残留 id 时 POST 仍创建新记录,不触发主键冲突(UNIQUE constraint failed: id 1555)。
func TestCreateTemplateIgnoresClientID(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// 预置 id=5 的模板(模拟前端编辑后 form 残留 id=5) + group 3
	gdb.Create(&model.CustomChain{ID: 3, Name: "grp", Parent: "MYFW-FORWARD", Table: "filter"})
	gdb.Create(&model.PolicyTemplate{ID: 5, Name: "existing", Action: "ACCEPT", GroupID: 3})
	h := BuildWebHandler(gdb, time.Minute)

	// 传残留 id=5 + 新名称,应创建新记录(id 自增,非 5)
	body := `{"id":5,"name":"new-tpl","group_id":3,"action":"ACCEPT"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var tpl model.PolicyTemplate
	if err := json.Unmarshal(w.Body.Bytes(), &tpl); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if tpl.ID == 5 {
		t.Fatal("应忽略前端传入 id=5,创建新自增 id,而非复用 5 致主键冲突")
	}
	if tpl.Name != "new-tpl" {
		t.Fatalf("name 应为 new-tpl, got %q", tpl.Name)
	}
}

// TestCreateTemplateMARKNoSourceOK 验证 MARK 白名单模板创建时源地址可选(问题 2 修复):
// 模板是可复用骨架,源地址留实例化时填,模板级不强制(原 rulespec 强制源导致模板无法创建)。
func TestCreateTemplateMARKNoSourceOK(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.Mark{Name: "dev", Value: 15, Description: "开发"})
	h := BuildWebHandler(gdb, time.Minute)

	// MARK 模板无源,有端口+标记值,应创建成功(源留实例化)
	body := `{"name":"mark-skel","action":"MARK","mark":15,"protocol":"TCP","port_range":"8080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
}

// TestCreateInstanceMARKNoSourceRejected 验证实例 MARK 无源被 400 拒绝(问题 2 修复):
// 模板可无源(骨架),但实例编译下发需要源(白名单放行规则),实例层校验 MARK 源必填。
func TestCreateInstanceMARKNoSourceRejected(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.Mark{Name: "dev", Value: 15, Description: "开发"})
	h := BuildWebHandler(gdb, time.Minute)

	// 直接新建实例(template_id=0)MARK 无源,应 400
	body := `{"name":"bad-inst","action":"MARK","mark":15,"protocol":"TCP","port_range":"8080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/instances", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400, body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "源") {
		t.Fatalf("error 应提示源地址, body=%s", w.Body.String())
	}
}

// TestInstantiateMARKTemplateWithBodySource 验证从无源 MARK 模板实例化时 body.source 覆盖(问题 2 修复):
// 模板无源(骨架),实例化时 body 传源覆盖,实例源=body.source,通过实例层 MARK 源校验。
func TestInstantiateMARKTemplateWithBodySource(t *testing.T) {
	gdb, err := db.Open(db.Config{
		Driver:       db.DriverSQLite,
		DSN:          "file::memory:",
		MaxOpenConns: 1,
		MaxIdleConns: 1,
		LogLevel:     gormlogger.Silent,
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Migrate(gdb); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	gdb.Create(&model.Mark{Name: "dev", Value: 15, Description: "开发"})
	// 无源 MARK 模板(骨架:端口+标记,源留实例化)
	gdb.Create(&model.PolicyTemplate{ID: 1, Name: "mark-skel", Action: "MARK", Mark: 15, Protocol: "TCP", PortRange: "8080", SpecVersion: 1})
	h := BuildWebHandler(gdb, time.Minute)

	body := `{"template_id":1,"name":"inst","source":"10.0.0.0/24"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/nodes/n1/instances", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status: got %d, want 201, body=%s", w.Code, w.Body.String())
	}
	var inst model.NodePolicyInstance
	if err := json.Unmarshal(w.Body.Bytes(), &inst); err != nil {
		t.Fatalf("unmarshal: %v, body=%s", err, w.Body.String())
	}
	if inst.Source != "10.0.0.0/24" {
		t.Fatalf("实例 source 应为 body 覆盖值 10.0.0.0/24, got %q", inst.Source)
	}
}