package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/task"
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

	// 从模板实例化:全量复制模板参数到该节点,可选立即应用
	g.POST("/nodes/:id/instances", func(c *gin.Context) {
		nodeID := c.Param("id")
		var body struct {
			TemplateID uint   `json:"template_id"`
			Name       string `json:"name"`
			Apply      bool   `json:"apply"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		var tpl model.PolicyTemplate
		if err := db.First(&tpl, body.TemplateID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		name := body.Name
		if name == "" {
			name = tpl.Name
		}
		inst := model.NodePolicyInstance{
			TemplateID: tpl.ID, NodeID: nodeID, Name: name,
			GroupID: tpl.GroupID, Source: tpl.Source, Destination: tpl.Destination,
			Protocol: tpl.Protocol, PortRange: tpl.PortRange, Action: tpl.Action,
			Mark: tpl.Mark, NatTo: tpl.NatTo, SourceGroup: tpl.SourceGroup,
			DestinationGroup: tpl.DestinationGroup, MatchMark: tpl.MatchMark,
			MarkACLGroupID: tpl.MarkACLGroupID, Priority: tpl.Priority,
			Description: tpl.Description, Enabled: true,
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
		inst.GroupID = tpl.GroupID
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
		inst.MarkACLGroupID = tpl.MarkACLGroupID
		inst.Priority = tpl.Priority
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
		c.JSON(http.StatusOK, gin.H{"tasks": tasks})
	})
}

// instanceDrift 比较实例与模板当前参数,任一规则字段不同即 drift。
func instanceDrift(inst *model.NodePolicyInstance, tpl *model.PolicyTemplate) bool {
	return inst.GroupID != tpl.GroupID || inst.Source != tpl.Source ||
		inst.Destination != tpl.Destination || inst.Protocol != tpl.Protocol ||
		inst.PortRange != tpl.PortRange || inst.Action != tpl.Action ||
		inst.Mark != tpl.Mark || inst.NatTo != tpl.NatTo ||
		inst.SourceGroup != tpl.SourceGroup || inst.DestinationGroup != tpl.DestinationGroup ||
		inst.MatchMark != tpl.MatchMark || inst.MarkACLGroupID != tpl.MarkACLGroupID ||
		inst.Priority != tpl.Priority
}

func parseTplID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return 0, false
	}
	return uint(n), true
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
