package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/simulator"
	"iptables-tool/internal/model"
)

// registerSimulateRoutes 注册流量仿真预演(计划二)路由:
//
//	POST /api/v1/simulate  入参 node_id + flow 五元组,返回命中路径与最终判定
//
// 语义:流量预演收敛到节点级别--基于该节点当前实际生效的期望态规则
// (compiler.CompileForNode 编译产出的 CompiledRule)进行无状态逻辑推演,
// 不依赖 Agent 在线,不接受外部规则集内联(非节点级入口已移除)。
// 与规则库版本档案共用同一套"期望态"来源。首版仅 filter 表无状态匹配,
// 详见 simulator 包文档。
func registerSimulateRoutes(r gin.IRouter, comp *compiler.Compiler, db *gorm.DB) {
	r.POST("/api/v1/simulate", func(c *gin.Context) {
		var body struct {
			NodeID string         `json:"node_id"`
			Flow   simulator.Flow `json:"flow"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if body.NodeID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "node_id is required"})
			return
		}

		// 节点必须存在:期望态源自该节点实例/链/地址组,不存在属参数错误。
		var node model.Node
		if err := db.WithContext(c.Request.Context()).Where("id = ?", body.NodeID).First(&node).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
			return
		}
		rules, sets, chains, err := comp.CompileForNode(c.Request.Context(), body.NodeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		res, err := simulator.Evaluate(body.Flow, rules, chains, sets)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"verdict": res.Verdict, "steps": res.Steps, "note": res.Note})
	})
}
