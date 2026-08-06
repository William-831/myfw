package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/controller/task"
	"iptables-tool/internal/controller/templateio"
	"iptables-tool/internal/model"
)

// registerTemplateRoutes 挂载 C 档策略模板库 + 节点策略实例 API。
// 模板库只维护规则骨架(无节点);节点实例从模板全量复制参数,编译只读实例。
func registerTemplateRoutes(r gin.IRouter, db *gorm.DB, co *task.Coordinator, auditSink *audit.Sink) {
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
		body.ID = id
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
			TemplateName string `json:"template_name"`
			Drift        bool   `json:"drift"`
		}
		out := make([]instView, len(instances))
		for i := range instances {
			out[i].NodePolicyInstance = instances[i]
			if tpl, ok := templates[instances[i].TemplateID]; ok {
				out[i].TemplateName = tpl.Name
				out[i].Drift = instanceDrift(&instances[i], tpl)
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
			MarkACLGroupID   uint   `json:"mark_acl_group_id"`
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
				MarkACLGroupID: tpl.MarkACLGroupID, Priority: tpl.Priority,
				Description: tpl.Description, Enabled: true,
				SyncedTemplateUpdatedAt: tpl.UpdatedAt,
			}
		} else {
			// 直接新建:不依赖模板,template_id=0(无 drift/同步)
			if body.Name == "" {
				c.JSON(http.StatusBadRequest, gin.H{"error": "需填写实例名称"})
				return
			}
			// MARK 白名单拦截:group_id 可空(规则落内置链);其他场景 group_id 必填
			isMarkACL := body.Action == "MARK" && (body.Source != "" || body.SourceGroup != "") && body.PortRange != ""
			if body.GroupID == 0 && !isMarkACL {
				c.JSON(http.StatusBadRequest, gin.H{"error": "需选择策略组"})
				return
			}
			inst = model.NodePolicyInstance{
				TemplateID: 0, NodeID: nodeID, Name: body.Name,
				GroupID: body.GroupID, Direction: body.Direction, Source: body.Source, Destination: body.Destination,
				Protocol: body.Protocol, PortRange: body.PortRange, Action: body.Action,
				Mark: body.Mark, NatTo: body.NatTo, SourceGroup: body.SourceGroup,
				DestinationGroup: body.DestinationGroup, MatchMark: body.MatchMark,
				MarkACLGroupID: body.MarkACLGroupID, Priority: body.Priority,
				Description: body.Description, Enabled: true,
			}
		}
		if err := policy.ValidateFields(fieldsFromInstance(&inst)); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		// MARK 白名单拦截:group_id 可空;其他场景 group_id 必填
		isMarkACL := body.Action == "MARK" && (body.Source != "" || body.SourceGroup != "") && body.PortRange != ""
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
		db.First(&inst, id)
		if err := db.Delete(&model.NodePolicyInstance{}, id).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditInst(auditSink, c, "delete", id, inst.Name, inst.NodeID)
		c.Status(http.StatusNoContent)
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
		// 数值/调度字段始终同步(通用参数,由模板定义)
		inst.GroupID = tpl.GroupID
		inst.Direction = tpl.Direction
		inst.Mark = tpl.Mark
		inst.MatchMark = tpl.MatchMark
		inst.MarkACLGroupID = tpl.MarkACLGroupID
		inst.Priority = tpl.Priority
		// 字符串字段:仅当模板有值时才覆盖。模板为空 = 该字段是节点特有参数
		// (由实例自定义,如节点 IP),同步时保留实例原值,避免清空实例配置。
		if tpl.Source != "" {
			inst.Source = tpl.Source
		}
		if tpl.Destination != "" {
			inst.Destination = tpl.Destination
		}
		if tpl.Protocol != "" {
			inst.Protocol = tpl.Protocol
		}
		if tpl.PortRange != "" {
			inst.PortRange = tpl.PortRange
		}
		if tpl.Action != "" {
			inst.Action = tpl.Action
		}
		if tpl.NatTo != "" {
			inst.NatTo = tpl.NatTo
		}
		if tpl.SourceGroup != "" {
			inst.SourceGroup = tpl.SourceGroup
		}
		if tpl.DestinationGroup != "" {
			inst.DestinationGroup = tpl.DestinationGroup
		}
		inst.Applied = false // 同步后参数变更,需重新下发
		inst.SyncedTemplateUpdatedAt = tpl.UpdatedAt // 同步完成,记录模板当前版本
		if err := db.Save(&inst).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditInst(auditSink, c, "sync", id, inst.Name, inst.NodeID)
		c.JSON(http.StatusOK, inst)
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
		tasks, err := co.Submit(c.Request.Context(), 0, []string{nodeID}, task.SubmitOpts{
			Author:          actor(c),
			AutoApprove:     body.AutoApprove,
			ConfirmDeadline: time.Duration(body.ConfirmDeadlineSeconds) * time.Second,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 下发后 applied 反映节点实际状态 = enabled:启用实例已下发(applied=true),
		// 禁用实例规则已移除(applied=false)。乐观标记--apply 失败时由保护期回滚兜底。
		db.Model(&model.NodePolicyInstance{}).Where("node_id = ?", nodeID).Update("applied", gorm.Expr("enabled"))
		c.JSON(http.StatusOK, gin.H{"tasks": tasks})
	})
}

// instanceDrift 判断模板是否在实例上次同步后更新过。
// 仅当模板 UpdatedAt 晚于实例 SyncedTemplateUpdatedAt 才视为 drift(可同步);
// 实例自身编辑不视为 drift(用户主动偏离模板,不提示同步)。
func instanceDrift(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) bool {
	return tpl.UpdatedAt.After(inst.SyncedTemplateUpdatedAt)
}

func parseTplID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return 0, false
	}
	return uint(n), true
}

// fieldsFromTemplate / fieldsFromInstance 从模板/实例抽取规则字段子集,供
// ValidateFields 统一校验(MARK 取值、白名单需端口等),杜绝误配静默落库。
func fieldsFromTemplate(t *model.PolicyTemplate) policy.Fields {
	return policy.Fields{
		Action: t.Action, Direction: t.Direction, Mark: t.Mark, MatchMark: t.MatchMark, NatTo: t.NatTo,
		Protocol: t.Protocol, PortRange: t.PortRange, Source: t.Source,
		SourceGroup: t.SourceGroup,
	}
}

func fieldsFromInstance(i *model.NodePolicyInstance) policy.Fields {
	return policy.Fields{
		Action: i.Action, Direction: i.Direction, Mark: i.Mark, MatchMark: i.MatchMark, NatTo: i.NatTo,
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
