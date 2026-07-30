package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"iptables-tool/internal/controller/auth"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/controller/task"
	"iptables-tool/internal/model"
)

// registerPolicyRoutes mounts M7's Policy CRUD + Apply endpoints.
//
// ⚠️ C 档后前端已改用 templates/instances(见 template_routes.go),本路由保留供
// e2e 测试与旧 Policy 数据兼容,不再被前端调用。Policy 表仍作迁移源/审计保留。
func registerPolicyRoutes(r gin.IRouter, svc *policy.Service, co *task.Coordinator, comp *compiler.Compiler, auditSink *audit.Sink) {
	g := r.Group("/api/v1/policies")
	g.POST("", func(c *gin.Context) { createPolicy(c, svc, auditSink) })
	g.GET("", func(c *gin.Context) { listPolicies(c, svc) })
	g.GET("/:id", func(c *gin.Context) { getPolicy(c, svc) })
	g.PUT("/:id", func(c *gin.Context) { updatePolicy(c, svc, auditSink) })
	g.DELETE("/:id", func(c *gin.Context) { deletePolicy(c, svc, auditSink) })

	g.POST("/:id/apply", func(c *gin.Context) { applyOnePolicy(c, svc, co, comp) })
	g.POST("/apply-all", func(c *gin.Context) { applyAllPolicies(c, co, comp) })

	// 策略变更审批（阶段5）：提交变更 -> 审批 -> 生效并下发关联节点
	g.POST("/:id/submit", func(c *gin.Context) { submitPolicyChange(c, svc) })
	g.GET("/:id/versions", func(c *gin.Context) { listPolicyVersions(c, svc) })
	g.POST("/:id/versions/:vid/approve", func(c *gin.Context) { approvePolicyVersion(c, svc, co, comp) })
	g.POST("/:id/versions/:vid/reject", func(c *gin.Context) { rejectPolicyVersion(c, svc) })
}

// --- CRUD ------------------------------------------------------------------

func createPolicy(c *gin.Context, svc *policy.Service, auditSink *audit.Sink) {
	var in policy.PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p, err := svc.Create(c.Request.Context(), in, actor(c))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	auditPolicy(auditSink, c, "create", p.ID, p.Name)
	c.JSON(http.StatusCreated, p)
}

func listPolicies(c *gin.Context, svc *policy.Service) {
	list, err := svc.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": list})
}

func getPolicy(c *gin.Context, svc *policy.Service) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	p, err := svc.Get(c.Request.Context(), id)
	if err != nil {
		respondPolicyErr(c, err)
		return
	}
	c.JSON(http.StatusOK, p)
}

func updatePolicy(c *gin.Context, svc *policy.Service, auditSink *audit.Sink) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var in policy.PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	p, err := svc.Update(c.Request.Context(), id, in, actor(c))
	if err != nil {
		respondPolicyErr(c, err)
		return
	}
	auditPolicy(auditSink, c, "update", p.ID, p.Name)
	c.JSON(http.StatusOK, p)
}

func deletePolicy(c *gin.Context, svc *policy.Service, auditSink *audit.Sink) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	// 删除前查策略名,审计留痕(避免删后丢失上下文)
	var name string
	if p, err := svc.Get(c.Request.Context(), id); err == nil {
		name = p.Name
	}
	if err := svc.Delete(c.Request.Context(), id); err != nil {
		respondPolicyErr(c, err)
		return
	}
	auditPolicy(auditSink, c, "delete", id, name)
	c.Status(http.StatusNoContent)
}

// --- Apply (now via Coordinator) -------------------------------------------

type applyPolicyReq struct {
	AutoApprove            bool  `json:"auto_approve"`
	ConfirmDeadlineSeconds int64 `json:"confirm_deadline_seconds"`
	WaitForSeconds         int64 `json:"wait_for_seconds"` // only used when auto_approve=true
}

func applyOnePolicy(c *gin.Context, svc *policy.Service, co *task.Coordinator, comp *compiler.Compiler) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	p, err := svc.Get(c.Request.Context(), id)
	if err != nil {
		respondPolicyErr(c, err)
		return
	}

	var body applyPolicyReq
	_ = c.ShouldBindJSON(&body)

	nodeIDs, err := comp.TargetNodes(c.Request.Context(), p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(nodeIDs) == 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"error":   "policy has no matching target nodes",
			"policy":  p.ID,
			"targets": p.Targets,
		})
		return
	}

	tasks, err := co.Submit(c.Request.Context(), p.ID, nodeIDs, task.SubmitOpts{
		Author:          actor(c),
		AutoApprove:     body.AutoApprove,
		ConfirmDeadline: time.Duration(body.ConfirmDeadlineSeconds) * time.Second,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// When auto_approve is true the tasks already transitioned through
	// DISPATCHING/APPLYING/CONFIRM_WAIT. We wait for the result so the
	// caller gets a synchronous answer like M6 did.
	if body.AutoApprove {
		c.JSON(http.StatusOK, gin.H{
			"policy_id": p.ID,
			"tasks":     tasks,
		})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"policy_id": p.ID,
		"tasks":     tasks,
		"message":   "tasks created in PENDING_APPROVAL state; approve via POST /api/v1/tasks/:id/approve",
	})
}

func applyAllPolicies(c *gin.Context, co *task.Coordinator, comp *compiler.Compiler) {
	var body applyPolicyReq
	_ = c.ShouldBindJSON(&body)

	nodeIDs, err := comp.AllTargetedNodes(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(nodeIDs) == 0 {
		c.JSON(http.StatusOK, gin.H{"tasks": []any{}, "note": "no enabled policies target any node"})
		return
	}

	tasks, err := co.Submit(c.Request.Context(), 0, nodeIDs, task.SubmitOpts{
		Author:          actor(c),
		AutoApprove:     body.AutoApprove,
		ConfirmDeadline: time.Duration(body.ConfirmDeadlineSeconds) * time.Second,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if body.AutoApprove {
		c.JSON(http.StatusOK, gin.H{"tasks": tasks})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"tasks":   tasks,
		"message": "tasks created in PENDING_APPROVAL; approve via POST /api/v1/tasks/:id/approve",
	})
}

// --- 变更审批（阶段5）-------------------------------------------------------

func submitPolicyChange(c *gin.Context, svc *policy.Service) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	var in policy.PolicyInput
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	v, err := svc.SubmitChange(c.Request.Context(), id, in, actor(c))
	if err != nil {
		respondPolicyErr(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"version": v,
		"message": "变更已提交，待审批；通过 POST /api/v1/policies/:id/versions/:vid/approve 生效",
	})
}

func listPolicyVersions(c *gin.Context, svc *policy.Service) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	versions, err := svc.ListVersions(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"versions": versions})
}

func approvePolicyVersion(c *gin.Context, svc *policy.Service, co *task.Coordinator, comp *compiler.Compiler) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	vid, ok := parseVersionID(c)
	if !ok {
		return
	}
	p, err := svc.ApproveChange(c.Request.Context(), id, vid, actor(c))
	if err != nil {
		respondPolicyErr(c, err)
		return
	}
	// 审批通过后，自动下发到关联节点
	nodeIDs, err := comp.TargetNodes(c.Request.Context(), p)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"policy": p, "warning": "approved but dispatch failed: " + err.Error()})
		return
	}
	tasks := []any{}
	if len(nodeIDs) > 0 {
		t, err := co.Submit(c.Request.Context(), p.ID, nodeIDs, task.SubmitOpts{
			Author:          actor(c),
			AutoApprove:     false,
			ConfirmDeadline: 5 * time.Minute,
		})
		if err == nil {
			for _, tk := range t {
				tasks = append(tasks, tk)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"policy": p, "tasks": tasks})
}

func rejectPolicyVersion(c *gin.Context, svc *policy.Service) {
	id, ok := parseID(c)
	if !ok {
		return
	}
	vid, ok := parseVersionID(c)
	if !ok {
		return
	}
	if err := svc.RejectChange(c.Request.Context(), id, vid); err != nil {
		respondPolicyErr(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "version rejected"})
}

// --- helpers ---------------------------------------------------------------

func parseID(c *gin.Context) (uint, bool) {
	raw := c.Param("id")
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad policy id"})
		return 0, false
	}
	return uint(n), true
}

func parseVersionID(c *gin.Context) (uint, bool) {
	raw := c.Param("vid")
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad version id"})
		return 0, false
	}
	return uint(n), true
}

func respondPolicyErr(c *gin.Context, err error) {
	if errors.Is(err, policy.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
}

// auditPolicy 记录策略 CRUD 审计:detail 精简为操作类型+策略ID+名称,
// 供审计列表"详情"列直接展示动作摘要,展开行再看完整字段。
func auditPolicy(auditSink *audit.Sink, c *gin.Context, op string, policyID uint, name string) {
	if auditSink == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{"op": op, "policy_id": policyID, "name": name})
	_ = auditSink.Write(c.Request.Context(), model.AuditLog{
		Actor:  actor(c),
		Action: "policy." + op,
		Detail: string(detail),
	})
}

func actor(c *gin.Context) string { return auth.ActorFromContext(c.Request.Context()) }
