package server

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// computeDashboardStats 聚合仪表盘统计(B2 缓存的计算函数)。
func computeDashboardStats(db *gorm.DB) (any, error) {
	var nodeCount, activeNodeCount, pendingNodeCount, abnormalNodeCount int64
	var policyCount, activePolicyCount int64
	var pendingTaskCount int64

	if err := db.Model(&model.Node{}).Count(&nodeCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Node{}).Where("status = ?", model.NodeStatusActive).Count(&activeNodeCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Node{}).Where("status = ?", model.NodeStatusPending).Count(&pendingNodeCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Node{}).Where("status = ?", model.NodeStatusAbnormal).Count(&abnormalNodeCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Policy{}).Count(&policyCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Policy{}).Where("enabled = ?", true).Count(&activePolicyCount).Error; err != nil {
		return nil, err
	}
	if err := db.Model(&model.Task{}).Where("status = ?", model.TaskPendingApproval).Count(&pendingTaskCount).Error; err != nil {
		return nil, err
	}
	return gin.H{
		"node_count":          nodeCount,
		"active_node_count":   activeNodeCount,
		"pending_node_count":  pendingNodeCount,
		"abnormal_node_count": abnormalNodeCount,
		"policy_count":        policyCount,
		"active_policy_count": activePolicyCount,
		"pending_task_count":  pendingTaskCount,
	}, nil
}

func registerDashboardRoutes(r gin.IRouter, db *gorm.DB, rc *ReadCache) {
	r.GET("/api/v1/dashboard/stats", func(c *gin.Context) {
		// B2:统计 7 次独立 COUNT 属高频只读聚合,5s TTL 缓存复用。
		stats, err := rc.GetOrCompute("dashboard:stats", 5*time.Second, func() (any, error) {
			return computeDashboardStats(db)
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, stats)
	})

	// 配置漂移统计:各节点"模板已更新但实例未跟"(模板 SpecVersion > 实例快照)的实例数。
	// 与运行时规则漂移(node.drift 审计)区分——前者是配置侧语义漂移,可一键同步治理(1.4)。
	r.GET("/api/v1/dashboard/config-drift", func(c *gin.Context) {
		var instances []model.NodePolicyInstance
		db.Where("template_id > 0").Find(&instances)
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
		type nodeDrift struct {
			NodeID string `json:"node_id"`
			Count  int    `json:"count"`
		}
		byNode := map[string]int{}
		total := 0
		for i := range instances {
			tpl, ok := templates[instances[i].TemplateID]
			if !ok || !instanceDrift(&instances[i], tpl) {
				continue
			}
			byNode[instances[i].NodeID]++
			total++
		}
		nodes := make([]nodeDrift, 0, len(byNode))
		for nid, cnt := range byNode {
			nodes = append(nodes, nodeDrift{NodeID: nid, Count: cnt})
		}
		sort.Slice(nodes, func(a, b int) bool { return nodes[a].NodeID < nodes[b].NodeID })
		c.JSON(http.StatusOK, gin.H{"total": total, "nodes": nodes})
	})
}
