package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/model"
)

func registerNodeRoutes(r gin.IRouter, db *gorm.DB, streamSvc *stream.Service) {
	g := r.Group("/api/v1/nodes")

	g.GET("/list", func(c *gin.Context) {
		var nodes []model.Node
		if err := db.Preload("Capability").Find(&nodes).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// 聚合每节点 drift 实例数(实例参数 vs 模板当前参数),供节点列表角标提示
		var instances []model.NodePolicyInstance
		db.Find(&instances)
		tplIDs := map[uint]struct{}{}
		for i := range instances {
			if instances[i].TemplateID != 0 {
				tplIDs[instances[i].TemplateID] = struct{}{}
			}
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
		driftCount := map[string]int{}
		for i := range instances {
			if instances[i].TemplateID == 0 {
				continue
			}
			if tpl, ok := templates[instances[i].TemplateID]; ok {
				if instanceDrift(&instances[i], tpl) {
					driftCount[instances[i].NodeID]++
				}
			}
		}
		for i := range nodes {
			nodes[i].DriftCount = driftCount[nodes[i].ID]
		}
		// 聚合各节点当前有效证书过期时间(revoked=false 中 not_after 最大)
		if len(nodes) > 0 {
			ids := make([]string, 0, len(nodes))
			for i := range nodes {
				ids = append(ids, nodes[i].ID)
			}
			var certs []model.Certificate
			db.Where("node_id IN ? AND revoked = ?", ids, false).Find(&certs)
			certMap := make(map[string]time.Time, len(certs))
			for _, c := range certs {
				if t, ok := certMap[c.NodeID]; !ok || c.NotAfter.After(t) {
					certMap[c.NodeID] = c.NotAfter
				}
			}
			for i := range nodes {
				if t, ok := certMap[nodes[i].ID]; ok {
					nt := t
					nodes[i].CertNotAfter = &nt
				}
			}
		}
		c.JSON(http.StatusOK, gin.H{"nodes": nodes})
	})

	g.GET("/:id", func(c *gin.Context) {
		id := c.Param("id")
		var node model.Node
		if err := db.Preload("Capability").Where("id = ?", id).First(&node).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "node not found"})
			return
		}
		// 当前有效证书过期时间(revoked=false 中 not_after 最大)
		var cert model.Certificate
		if err := db.Where("node_id = ? AND revoked = ?", id, false).Order("not_after DESC").First(&cert).Error; err == nil {
			nt := cert.NotAfter
			node.CertNotAfter = &nt
		}
		c.JSON(http.StatusOK, node)
	})

	g.PUT("/:id", func(c *gin.Context) {
		id := c.Param("id")
		var body struct {
			Hostname string   `json:"hostname"`
			Labels   []string `json:"labels"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		updates := map[string]any{}
		if body.Hostname != "" {
			updates["hostname"] = body.Hostname
		}
		if body.Labels != nil {
			labelsJSON, _ := json.Marshal(body.Labels)
			updates["labels"] = string(labelsJSON)
		}

		if len(updates) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
			return
		}

		if err := db.Model(&model.Node{}).Where("id = ?", id).Updates(updates).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var node model.Node
		db.Preload("Capability").Where("id = ?", id).First(&node)
		c.JSON(http.StatusOK, node)
	})

	g.DELETE("/:id", func(c *gin.Context) {
		id := c.Param("id")
		if err := db.Model(&model.Node{}).Where("id = ?", id).Update("status", model.NodeStatusArchived).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	})

	// 续签证书：下发 RenewCert 指令到 Agent，Agent 异步续签后重建连接
	g.POST("/:id/renew-cert", func(c *gin.Context) {
		id := c.Param("id")
		if err := streamSvc.SendRenewCert(c.Request.Context(), id); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "message": "续签指令已下发"})
	})
}
