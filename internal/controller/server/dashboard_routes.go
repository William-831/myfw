package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

func registerDashboardRoutes(r gin.IRouter, db *gorm.DB) {
	r.GET("/api/v1/dashboard/stats", func(c *gin.Context) {
		var nodeCount, activeNodeCount, pendingNodeCount int64
		var policyCount, activePolicyCount int64
		var pendingTaskCount int64

		db.Model(&model.Node{}).Count(&nodeCount)
		db.Model(&model.Node{}).Where("status = ?", model.NodeStatusActive).Count(&activeNodeCount)
		db.Model(&model.Node{}).Where("status = ?", model.NodeStatusPending).Count(&pendingNodeCount)

		db.Model(&model.Policy{}).Count(&policyCount)
		db.Model(&model.Policy{}).Where("enabled = ?", true).Count(&activePolicyCount)

		db.Model(&model.Task{}).Where("status = ?", model.TaskPendingApproval).Count(&pendingTaskCount)

		c.JSON(http.StatusOK, gin.H{
			"node_count":          nodeCount,
			"active_node_count":   activeNodeCount,
			"pending_node_count":  pendingNodeCount,
			"policy_count":        policyCount,
			"active_policy_count": activePolicyCount,
			"pending_task_count":  pendingTaskCount,
		})
	})
}
