package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/controller/rulespec"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/controller/task"
	"iptables-tool/internal/controller/templateio"
	"iptables-tool/internal/model"
)

// registerTemplateRoutes 挂载 C 档策略模板库 + 节点策略实例 API。
// 模板库只维护规则骨架(无节点);节点实例从模板全量复制参数,编译只读实例。
func registerTemplateRoutes(r gin.IRouter, db *gorm.DB, co *task.Coordinator, auditSink *audit.Sink, streamSvc *stream.Service) {
	g := r.Group("/api/v1")

	// --- 模板 CRUD ---
	g.GET("/templates", func(c *gin.Context) {
		var tpls []model.PolicyTemplate
		if err := db.Order("id ASC").Find(&tpls).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"templates": tpls})
	})

	g.POST("/templates", func(c *gin.Context) {
		var tpl model.PolicyTemplate
		if err := c.ShouldBindJSON(&tpl); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := policy.ValidateFields(fieldsFromTemplate(&tpl)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if tpl.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "模板名称不能为空"})
			return
		}
		if !checkTemplateNameUnique(db, c, tpl.Name, 0) {
			return
		}
		if !checkTemplateGroup(db, c, tpl.GroupID) {
			return
		}
		if !checkMarkExists(db, c, tpl.Action, tpl.Mark) {
			return
		}
		// 新模板 spec 从 1 开始(漏洞 A:drift 判据改用 SpecVersion)
		tpl.SpecVersion = 1
		if err := db.Create(&tpl).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditTpl(auditSink, c, "create", tpl.ID, tpl.Name)
		c.JSON(http.StatusCreated, tpl)
	})

	g.PUT("/templates/:id", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		var body model.PolicyTemplate
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := policy.ValidateFields(fieldsFromTemplate(&body)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !checkTemplateGroup(db, c, body.GroupID) {
			return
		}
		if !checkMarkExists(db, c, body.Action, body.Mark) {
			return
		}
		// 规则字段脏检查:仅规则字段变更才递增 SpecVersion(漏洞 A 修复),
		// 改 Name/Description 等非规则字段不触发实例 drift。
		var orig model.PolicyTemplate
		if err := db.First(&orig, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		if !checkTemplateNameUnique(db, c, body.Name, id) {
			return
		}
		if templateSpecChanged(&orig, &body) {
			body.SpecVersion = orig.SpecVersion + 1
		} else {
			body.SpecVersion = orig.SpecVersion
		}
		body.ID = id
		body.CreatedAt = orig.CreatedAt // 保留创建时间,防前端未回传导致清零
		if err := db.Save(&body).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditTpl(auditSink, c, "update", id, body.Name)
		c.JSON(http.StatusOK, body)
	})

	g.DELETE("/templates/:id", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		// 引用检查:模板被节点实例引用时拒绝删除,避免产生孤儿实例
		// (无法 sync、drift 不再提示但规则仍在节点生效,漏洞 B 修复)。
		var refCount int64
		db.Model(&model.NodePolicyInstance{}).Where("template_id = ?", id).Count(&refCount)
		if refCount > 0 {
			c.JSON(http.StatusConflict, gin.H{
				"error": fmt.Sprintf("该模板仍被 %d 个节点实例引用,请先移除实例后再删除", refCount),
			})
			return
		}
		if err := db.Delete(&model.PolicyTemplate{}, id).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditTpl(auditSink, c, "delete", id, "")
		c.Status(http.StatusNoContent)
	})

	// --- 模板导入导出 ---
	g.GET("/templates/export", func(c *gin.Context) {
		bundle, err := templateio.Export(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"bundle": bundle})
	})

	g.POST("/templates/import", func(c *gin.Context) {
		var body struct {
			Policy templateio.ImportPolicy `json:"policy"`
			Bundle *templateio.Bundle      `json:"bundle"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if body.Bundle == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bundle is required"})
			return
		}
		if body.Policy == "" {
			body.Policy = templateio.ImportSkip
		}
		result, err := templateio.Import(db, body.Bundle, body.Policy)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if auditSink != nil {
			detail, _ := json.Marshal(map[string]any{
				"op":     "import",
				"policy": string(body.Policy),
				"result": result,
			})
			_ = auditSink.Write(c.Request.Context(), model.AuditLog{
				Actor:  actor(c),
				Action: "template.import",
				Detail: string(detail),
			})
		}
		c.JSON(http.StatusOK, result)
	})

	// --- 节点实例 ---
	g.GET("/nodes/:id/instances", func(c *gin.Context) {
		nodeID := c.Param("id")
		var instances []model.NodePolicyInstance
		if err := db.Where("node_id = ?", nodeID).Order("priority ASC, id ASC").Find(&instances).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 加载相关模板计算 drift + 模板名
		tplIDs := map[uint]struct{}{}
		for i := range instances {
			tplIDs[instances[i].TemplateID] = struct{}{}
		}
		templates := map[uint]*model.PolicyTemplate{}
		if len(tplIDs) > 0 {
			ids := make([]uint, 0, len(tplIDs))
			for id := range tplIDs {
				ids = append(ids, id)
			}
			var tpls []model.PolicyTemplate
			db.Where("id IN ?", ids).Find(&tpls)
			for i := range tpls {
				templates[tpls[i].ID] = &tpls[i]
			}
		}
		type instView struct {
			model.NodePolicyInstance
			TemplateName string   `json:"template_name"`
			Drift        bool     `json:"drift"`          // 模板 SpecVersion 领先实例快照(模板更新过)
			DriftFields  []string `json:"drift_fields"`   // 实例与模板当前参数不一致的规则字段
			Deviated     bool     `json:"deviated"`       // 实例参数 ≠ 模板当前参数(无论谁改的,含手动偏离)
			DeviatedFields []string `json:"deviated_fields"` // 同 drift_fields,实例侧偏离视角
		}
		out := make([]instView, len(instances))
		for i := range instances {
			out[i].NodePolicyInstance = instances[i]
			if tpl, ok := templates[instances[i].TemplateID]; ok {
				out[i].TemplateName = tpl.Name
				out[i].Drift = instanceDrift(&instances[i], tpl)
				out[i].DriftFields = instanceDiffFields(&instances[i], tpl)
				out[i].Deviated = instanceDeviated(&instances[i], tpl)
				out[i].DeviatedFields = out[i].DriftFields
			}
		}
		c.JSON(http.StatusOK, gin.H{"instances": out})
	})

	// 为节点添加实例:template_id>0 从模板实例化(全量复制参数);
	// template_id=0 直接新建(不依赖模板,无 drift/同步),用 body 完整参数创建。
	g.POST("/nodes/:id/instances", func(c *gin.Context) {
		nodeID := c.Param("id")
		var body struct {
			TemplateID       uint   `json:"template_id"`
			Name             string `json:"name"`
			Apply            bool   `json:"apply"`
			GroupID          uint   `json:"group_id"`
			Direction        string `json:"direction"`
			Source           string `json:"source"`
			Destination      string `json:"destination"`
			Protocol         string `json:"protocol"`
			PortRange        string `json:"port_range"`
			Action           string `json:"action"`
			Mark             uint32 `json:"mark"`
			NatTo            string `json:"nat_to"`
			SourceGroup      string `json:"source_group"`
			DestinationGroup string `json:"destination_group"`
			MatchMark        uint32 `json:"match_mark"`
			Priority         int    `json:"priority"`
			Description      string `json:"description"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var inst model.NodePolicyInstance
		if body.TemplateID > 0 {
			// 从模板实例化:全量复制模板参数
			var tpl model.PolicyTemplate
			if err := db.First(&tpl, body.TemplateID).Error; err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
				return
			}
			name := body.Name
			if name == "" {
				name = tpl.Name
			}
			inst = model.NodePolicyInstance{
				TemplateID: tpl.ID, NodeID: nodeID, Name: name,
				GroupID: tpl.GroupID, Direction: tpl.Direction, Source: tpl.Source, Destination: tpl.Destination,
				Protocol: tpl.Protocol, PortRange: tpl.PortRange, Action: tpl.Action,
				Mark: tpl.Mark, NatTo: tpl.NatTo, SourceGroup: tpl.SourceGroup,
				DestinationGroup: tpl.DestinationGroup, MatchMark: tpl.MatchMark,
				Priority: tpl.Priority,
				Description: tpl.Description, Enabled: true,
				SyncedSpecVersion:       tpl.SpecVersion, // 实例化即快照模板 spec(漏洞 A)
				SyncedTemplateUpdatedAt: tpl.UpdatedAt,
			}
		} else {
			// 直接新建:不依赖模板,template_id=0(无 drift/同步)
			if body.Name == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "需填写实例名称"})
				return
			}
			// MARK 白名单拦截:group_id 可空(规则落内置链);其他场景 group_id 必填
			isMarkACL := rulespec.IsMarkWhitelist(body.Action, body.Source, body.SourceGroup, body.PortRange)
			if body.GroupID == 0 && !isMarkACL {
				c.JSON(http.StatusBadRequest, gin.H{"error": "需选择策略组"})
				return
			}
			inst = model.NodePolicyInstance{
				TemplateID: 0, NodeID: nodeID, Name: body.Name,
				GroupID: body.GroupID, Source: body.Source, Destination: body.Destination,
				Protocol: body.Protocol, PortRange: body.PortRange, Action: body.Action,
				Mark: body.Mark, NatTo: body.NatTo, SourceGroup: body.SourceGroup,
				DestinationGroup: body.DestinationGroup, MatchMark: body.MatchMark,
				Priority: body.Priority,
				Description: body.Description, Enabled: true,
			}
		}
		// 非 MARK 动作 Direction 字段无意义,统一强制清空(覆盖模板实例化/直接新建两条路径)
		if inst.Action != "MARK" {
			inst.Direction = ""
		}
		if err := policy.ValidateFields(fieldsFromInstance(&inst)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !checkMarkExists(db, c, inst.Action, inst.Mark) {
			return
		}
		if err := db.Create(&inst).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditInst(auditSink, c, "create", inst.ID, inst.Name, nodeID)
		if body.Apply {
			_, _ = co.Submit(c.Request.Context(), 0, []string{nodeID}, task.SubmitOpts{
				Author: actor(c), AutoApprove: true,
			})
		}
		c.JSON(http.StatusCreated, inst)
	})

	g.PUT("/instances/:id", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		var body model.NodePolicyInstance
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		body.ID = id
		// 非 MARK 动作 Direction 字段无意义,强制清空(防客户端误传方向值)
		if body.Action != "MARK" {
			body.Direction = ""
		}
		// applied 语义 = "节点上是否有该实例的规则":
		//   禁用已下发实例 -> 节点规则仍在(待下次 dispatch 移除),保留 applied=true,
		//     供 Submit 识别"待禁用"实例(enabled=false AND applied=true)生成 -D 移除预览;
		//   其他变更(参数改动/启用/禁用未下发实例) -> 节点规则将与参数不符,置 applied=false 待下发。
		var orig model.NodePolicyInstance
		db.First(&orig, id)
		if !body.Enabled && orig.Enabled && orig.Applied {
			body.Applied = true
		} else {
			body.Applied = false
		}
		if err := policy.ValidateFields(fieldsFromInstance(&body)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if !checkMarkExists(db, c, body.Action, body.Mark) {
			return
		}
		// MARK 白名单拦截:group_id 可空;其他场景 group_id 必填
		isMarkACL := rulespec.IsMarkWhitelist(body.Action, body.Source, body.SourceGroup, body.PortRange)
		if body.GroupID == 0 && !isMarkACL {
			c.JSON(http.StatusBadRequest, gin.H{"error": "需选择策略组"})
			return
		}
		if err := db.Save(&body).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditInst(auditSink, c, "update", id, body.Name, body.NodeID)
		c.JSON(http.StatusOK, body)
	})

	g.DELETE("/instances/:id", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		var inst model.NodePolicyInstance
		if err := db.First(&inst, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
			return
		}
		// 节点上无规则(applied=false):直接删 DB 记录,无需下发移除
		if !inst.Applied {
			if err := db.Delete(&model.NodePolicyInstance{}, id).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			auditInst(auditSink, c, "delete", id, inst.Name, inst.NodeID)
			c.Status(http.StatusNoContent)
			return
		}
		// 节点上有规则(applied=true):走 dispatch 移除 + 进保护期,误删可回滚
		// 连接预检:节点未连接无法下发移除指令
		connected := false
		for _, nid := range streamSvc.Reg.Connected() {
			if nid == inst.NodeID {
				connected = true
				break
			}
		}
		if !connected {
			c.JSON(http.StatusConflict, gin.H{"error": "节点未连接,无法移除规则"})
			return
		}
		// 原子移除:事务内创建 task + 标记实例并关联 task_id,dispatch 失败自动恢复实例
		// (不再有"pending_delete=true 但 task_id 未关联"的孤儿态,漏洞 G 修复)。
		t, err := co.SubmitRemoval(c.Request.Context(), inst.ID, task.SubmitOpts{
			Author:      actor(c),
			AutoApprove: true,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "移除下发失败: " + err.Error()})
			return
		}
		auditInst(auditSink, c, "delete", id, inst.Name, inst.NodeID)
		c.JSON(http.StatusAccepted, gin.H{
			"task_id": t.ID,
			"message": "已进入保护期,可在保护期面板确认或回滚",
		})
	})

	// drift 同步预览:返回实例当前 vs 模板最新的字段级 diff(不落库)。
	// 前端 sync 确认前展示"将覆盖哪些字段",降低手动同步认知负担(配置侧漂移治理 1.2)。
	g.POST("/instances/:id/sync-preview", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		var inst model.NodePolicyInstance
		if err := db.First(&inst, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
			return
		}
		var tpl model.PolicyTemplate
		if err := db.First(&tpl, inst.TemplateID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		fields := make([]gin.H, 0)
		for _, f := range instanceDiffFields(&inst, &tpl) {
			fields = append(fields, gin.H{
				"field":    f,
				"label":    instFieldLabel(f),
				"current":  instFieldValue(&inst, f),
				"template": tplFieldValue(&tpl, f),
			})
		}
		c.JSON(http.StatusOK, gin.H{"fields": fields})
	})

	// drift 同步:用模板最新参数覆盖实例(实例名/启用/节点保留)
	g.POST("/instances/:id/sync", func(c *gin.Context) {
		id, ok := parseTplID(c)
		if !ok {
			return
		}
		var inst model.NodePolicyInstance
		if err := db.First(&inst, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "instance not found"})
			return
		}
		var tpl model.PolicyTemplate
		if err := db.First(&tpl, inst.TemplateID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		// 全量覆盖:模板最新参数整体对齐实例(漏洞 E 修复)。
		// 模板字段清空同样传播到实例,不再有"非空才覆盖"造成的假同步。
		// 实例名/启用状态/删除流程状态是实例特有,保留不动。
		// 全量覆盖 + spec 快照(sync 与 sync-all 共用逻辑)
		applyTemplateToInstance(&inst, &tpl)
		if err := db.Save(&inst).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditInst(auditSink, c, "sync", id, inst.Name, inst.NodeID)
		c.JSON(http.StatusOK, inst)
	})

	// 节点级批量同步:同步该节点所有 drift(模板 SpecVersion 领先)实例。
	// 已同步/无模板引用实例跳过;不触发下发(applied 置 false,用户另行 dispatch)。
	// 配置侧漂移治理 1.3:一键同步全部,避免逐个手动 sync 的认知负担。
	g.POST("/nodes/:id/sync-all", func(c *gin.Context) {
		nodeID := c.Param("id")
		var instances []model.NodePolicyInstance
		if err := db.Where("node_id = ? AND template_id > 0", nodeID).Find(&instances).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		synced, skipped := 0, 0
		for i := range instances {
			var tpl model.PolicyTemplate
			if err := db.First(&tpl, instances[i].TemplateID).Error; err != nil {
				skipped++ // 模板已删(异常态),跳过
				continue
			}
			if !instanceDrift(&instances[i], &tpl) {
				skipped++
				continue
			}
			applyTemplateToInstance(&instances[i], &tpl)
			if err := db.Save(&instances[i]).Error; err != nil {
				skipped++
				continue
			}
			auditInst(auditSink, c, "sync", instances[i].ID, instances[i].Name, nodeID)
			synced++
		}
		c.JSON(http.StatusOK, gin.H{"synced": synced, "skipped": skipped})
	})

	// 节点级 dispatch:编译该节点所有 enabled 实例下发,走审批/保护期
	// (用 /dispatch 避免与 M5 ad-hoc /nodes/:id/apply 冲突)
	g.POST("/nodes/:id/dispatch", func(c *gin.Context) {
		nodeID := c.Param("id")
		var body struct {
			AutoApprove            bool  `json:"auto_approve"`
			ConfirmDeadlineSeconds int64 `json:"confirm_deadline_seconds"`
		}
		_ = c.ShouldBindJSON(&body)
		// 下发前连接预检:节点未连接时直接返回,不创建 task。
		connected := false
		for _, id := range streamSvc.Reg.Connected() {
			if id == nodeID {
				connected = true
				break
			}
		}
		if !connected {
			c.JSON(http.StatusConflict, gin.H{"error": "节点未连接,无法下发"})
			return
		}
		tasks, err := co.Submit(c.Request.Context(), 0, []string{nodeID}, task.SubmitOpts{
			Author:          actor(c),
			AutoApprove:     body.AutoApprove,
			ConfirmDeadline: time.Duration(body.ConfirmDeadlineSeconds) * time.Second,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// applied 标记由 Coordinator.handleResult 在 Agent 确认结果后更新:
		// 成功时 enabled→true,失败时全部回退 false。
		// 不在此处提前写入,避免节点离线时误显示"已下发"。
		c.JSON(http.StatusOK, gin.H{"tasks": tasks})
	})
}

// instanceDrift 判断模板规则字段是否在实例上次同步后更新过(可同步)。
// SpecVersion 主导:模板规则字段版本号大于实例快照版本 = drift;改模板名称/描述等
// 非规则字段不递增 SpecVersion,不误报 drift(漏洞 A 修复)。
// 兼容旧数据:模板 SpecVersion=0(存量模板未用新版编辑过)时回退 UpdatedAt 时间戳判据,
// 避免仅记 SyncedTemplateUpdatedAt 的存量实例漏报。
func instanceDrift(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) bool {
	if tpl.SpecVersion > 0 {
		return inst.SyncedSpecVersion < tpl.SpecVersion
	}
	return tpl.UpdatedAt.After(inst.SyncedTemplateUpdatedAt)
}

// instanceDiffFields 返回实例与模板当前参数不一致的规则字段名列表(配置侧漂移详情)。
// 字段集同 templateSpecChanged;描述等非规则字段不参与。用于 drift 角标字段级展示
// 与偏离检测,降低手动同步认知负担(用户可知具体哪些字段变了)。
func instanceDiffFields(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) []string {
	var fields []string
	if inst.GroupID != tpl.GroupID {
		fields = append(fields, "group_id")
	}
	if inst.Direction != tpl.Direction {
		fields = append(fields, "direction")
	}
	if inst.Source != tpl.Source {
		fields = append(fields, "source")
	}
	if inst.Destination != tpl.Destination {
		fields = append(fields, "destination")
	}
	if inst.Protocol != tpl.Protocol {
		fields = append(fields, "protocol")
	}
	if inst.PortRange != tpl.PortRange {
		fields = append(fields, "port_range")
	}
	if inst.Action != tpl.Action {
		fields = append(fields, "action")
	}
	if inst.Mark != tpl.Mark {
		fields = append(fields, "mark")
	}
	if inst.NatTo != tpl.NatTo {
		fields = append(fields, "nat_to")
	}
	if inst.SourceGroup != tpl.SourceGroup {
		fields = append(fields, "source_group")
	}
	if inst.DestinationGroup != tpl.DestinationGroup {
		fields = append(fields, "destination_group")
	}
	if inst.MatchMark != tpl.MatchMark {
		fields = append(fields, "match_mark")
	}
	if inst.Priority != tpl.Priority {
		fields = append(fields, "priority")
	}
	return fields
}

// instanceDeviated 判断实例参数是否手动偏离模板当前参数(不依赖 SpecVersion)。
// 与 instanceDrift 互补:drift 看"模板是否更新过",deviated 看"实例参数是否与模板当前不一致"。
func instanceDeviated(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) bool {
	return len(instanceDiffFields(inst, tpl)) > 0
}

// applyTemplateToInstance 用模板最新参数全量覆盖实例规则字段(漏洞 E 修复语义)。
// 实例名/启用/删除流程状态是实例特有保留;applied 置 false 待下发;spec 快照更新到模板最新。
// sync(单条)与 sync-all(批量)共用,避免同步逻辑分叉。
func applyTemplateToInstance(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) {
	inst.GroupID = tpl.GroupID
	inst.Direction = tpl.Direction
	inst.Source = tpl.Source
	inst.Destination = tpl.Destination
	inst.Protocol = tpl.Protocol
	inst.PortRange = tpl.PortRange
	inst.Action = tpl.Action
	inst.Mark = tpl.Mark
	inst.NatTo = tpl.NatTo
	inst.SourceGroup = tpl.SourceGroup
	inst.DestinationGroup = tpl.DestinationGroup
	inst.MatchMark = tpl.MatchMark
	inst.Priority = tpl.Priority
	inst.Description = tpl.Description
	inst.Applied = false
	inst.SyncedSpecVersion = tpl.SpecVersion
	inst.SyncedTemplateUpdatedAt = tpl.UpdatedAt
}

// instFieldLabel 规则字段中文名(sync 预览/偏离 tooltip 展示用)。
func instFieldLabel(name string) string {
	switch name {
	case "group_id":
		return "所属策略组"
	case "direction":
		return "流量方向"
	case "source":
		return "源地址"
	case "destination":
		return "目的地址"
	case "protocol":
		return "协议"
	case "port_range":
		return "端口"
	case "action":
		return "动作"
	case "mark":
		return "标记"
	case "nat_to":
		return "转换目标"
	case "source_group":
		return "源地址组"
	case "destination_group":
		return "目的地址组"
	case "match_mark":
		return "匹配标记"
	case "priority":
		return "优先级"
	}
	return name
}

// instFieldValue / tplFieldValue 按字段名取字符串值(sync 预览 diff 用)。
// 两类型规则字段集一致,分别 case;group_id/mark/match_mark/priority 转字符串展示。
func instFieldValue(inst *model.NodePolicyInstance, name string) string {
	switch name {
	case "group_id":
		return strconv.FormatUint(uint64(inst.GroupID), 10)
	case "direction":
		return inst.Direction
	case "source":
		return inst.Source
	case "destination":
		return inst.Destination
	case "protocol":
		return inst.Protocol
	case "port_range":
		return inst.PortRange
	case "action":
		return inst.Action
	case "mark":
		return strconv.FormatUint(uint64(inst.Mark), 10)
	case "nat_to":
		return inst.NatTo
	case "source_group":
		return inst.SourceGroup
	case "destination_group":
		return inst.DestinationGroup
	case "match_mark":
		return strconv.FormatUint(uint64(inst.MatchMark), 10)
	case "priority":
		return strconv.Itoa(inst.Priority)
	}
	return ""
}

func tplFieldValue(tpl *model.PolicyTemplate, name string) string {
	switch name {
	case "group_id":
		return strconv.FormatUint(uint64(tpl.GroupID), 10)
	case "direction":
		return tpl.Direction
	case "source":
		return tpl.Source
	case "destination":
		return tpl.Destination
	case "protocol":
		return tpl.Protocol
	case "port_range":
		return tpl.PortRange
	case "action":
		return tpl.Action
	case "mark":
		return strconv.FormatUint(uint64(tpl.Mark), 10)
	case "nat_to":
		return tpl.NatTo
	case "source_group":
		return tpl.SourceGroup
	case "destination_group":
		return tpl.DestinationGroup
	case "match_mark":
		return strconv.FormatUint(uint64(tpl.MatchMark), 10)
	case "priority":
		return strconv.Itoa(tpl.Priority)
	}
	return ""
}

func parseTplID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return 0, false
	}
	return uint(n), true
}

// checkTemplateNameUnique 校验模板 name 唯一(漏洞 K 修复),excludeID 排除自身(更新时)。
// 模板 name 唯一后,导入去重按 name 判断才可靠,不再出现重名只处理第一条的问题。
func checkTemplateNameUnique(db *gorm.DB, c *gin.Context, name string, excludeID uint) bool {
	q := db.Model(&model.PolicyTemplate{}).Where("name = ?", name)
	if excludeID > 0 {
		q = q.Where("id != ?", excludeID)
	}
	var cnt int64
	if err := q.Count(&cnt).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return false
	}
	if cnt > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "模板名称已存在"})
		return false
	}
	return true
}

// checkTemplateGroup 校验模板 group_id:>0 时必须指向存在的策略组,否则 400(漏洞 D 修复)。
// group_id=0 放行(模板不绑定组的宽松语义,如 MARK 白名单模板落内置链)。
func checkTemplateGroup(db *gorm.DB, c *gin.Context, groupID uint) bool {
	if groupID == 0 {
		return true
	}
	var grp model.CustomChain
	if err := db.First(&grp, groupID).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "策略组不存在"})
		return false
	}
	return true
}

// checkMarkExists 校验 MARK 规则的打标值存在于标记管理(Mark 表)。
// 标记语义(dev=开发/ops=运维等)由标记管理统一承载,规则 mark 字段存 value 引用;
// 数值合法性(mark 非零)由 rulespec 校验,此处补"必须已定义"的引用完整性,
// 与前端标记值下拉(从标记管理加载)一致,防御绕过 UI 直接传未定义值。
// 仅 MARK 动作需校验;MatchMark 为编译内部字段,不在此校验。
func checkMarkExists(db *gorm.DB, c *gin.Context, action string, mark uint32) bool {
	if action != "MARK" {
		return true
	}
	var m model.Mark
	if err := db.Where("value = ?", mark).First(&m).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("标记值 %d 未在标记管理中定义,请先在标记管理创建", mark)})
		return false
	}
	return true
}

// templateSpecChanged 判断模板规则字段是否变更,决定是否递增 SpecVersion(漏洞 A 修复)。
// 规则字段:方向/源/目的/协议/端口/动作/标记/转换/组引用/匹配标记/优先级/归属组;
// 非规则字段:名称/描述/启用——修改它们不触发节点实例 drift。
func templateSpecChanged(orig, next *model.PolicyTemplate) bool {
	return orig.GroupID != next.GroupID ||
		orig.Direction != next.Direction ||
		orig.Source != next.Source ||
		orig.Destination != next.Destination ||
		orig.Protocol != next.Protocol ||
		orig.PortRange != next.PortRange ||
		orig.Action != next.Action ||
		orig.Mark != next.Mark ||
		orig.NatTo != next.NatTo ||
		orig.SourceGroup != next.SourceGroup ||
		orig.DestinationGroup != next.DestinationGroup ||
		orig.MatchMark != next.MatchMark ||
		orig.Priority != next.Priority
}

// fieldsFromTemplate / fieldsFromInstance 从模板/实例抽取规则字段子集,供
// ValidateFields 统一校验(MARK 取值、白名单需端口等),杜绝误配静默落库。
func fieldsFromTemplate(t *model.PolicyTemplate) policy.Fields {
	dir := t.Direction
	if t.Action != "MARK" {
		dir = "" // 非 MARK 动作方向字段无意义,校验时传空
	}
	return policy.Fields{
		Action: t.Action, Direction: dir, Mark: t.Mark, MatchMark: t.MatchMark, NatTo: t.NatTo,
		Protocol: t.Protocol, PortRange: t.PortRange, Source: t.Source,
		SourceGroup: t.SourceGroup,
	}
}

func fieldsFromInstance(i *model.NodePolicyInstance) policy.Fields {
	dir := i.Direction
	if i.Action != "MARK" {
		dir = "" // 非 MARK 动作方向字段无意义,校验时传空
	}
	return policy.Fields{
		Action: i.Action, Direction: dir, Mark: i.Mark, MatchMark: i.MatchMark, NatTo: i.NatTo,
		Protocol: i.Protocol, PortRange: i.PortRange, Source: i.Source,
		SourceGroup: i.SourceGroup,
	}
}

func auditTpl(auditSink *audit.Sink, c *gin.Context, op string, id uint, name string) {
	if auditSink == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{"op": op, "template_id": id, "name": name})
	_ = auditSink.Write(c.Request.Context(), model.AuditLog{
		Actor:  actor(c),
		Action: "template." + op,
		Detail: string(detail),
	})
}

func auditInst(auditSink *audit.Sink, c *gin.Context, op string, id uint, name, nodeID string) {
	if auditSink == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{"op": op, "instance_id": id, "name": name})
	_ = auditSink.Write(c.Request.Context(), model.AuditLog{
		Actor:  actor(c),
		Action: "instance." + op,
		NodeID: nodeID,
		Detail: string(detail),
	})
}
