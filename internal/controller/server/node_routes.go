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

func registerNodeRoutes(r gin.IRouter, db *gorm.DB, streamSvc *stream.Service, rc *ReadCache) {
	g := r.Group("/api/v1/nodes")

	g.GET("/list", func(c *gin.Context) {
		// B2:节点列表聚合(全量 instances/templates/certs)是最高频只读接口,5s TTL 缓存复用。
		// 注意:online 字段来自 Registry 实时状态,不进缓存,每次实时覆盖。
		v, err := rc.GetOrCompute("nodes:list", 5*time.Second, func() (any, error) {
			return computeNodesList(db)
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		nodes := v.([]model.Node)
		// 实时覆盖 online(缓存只聚合 drift/证书,连接状态必须实时)
		connected := make(map[string]struct{}, 16)
		for _, id := range streamSvc.Reg.Connected() {
			connected[id] = struct{}{}
		}
		for i := range nodes {
			_, nodes[i].Online = connected[nodes[i].ID]
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

	// 节点/实例变更后失效列表缓存(写操作调用,保证一致性)
	invalidateNodesList := func() { rc.DeletePrefix("nodes") }

	g.PUT("/:id", func(c *gin.Context) {
		id := c.Param("id")
		var body struct {
			Hostname string   `json:"hostname"`
			Name     string   `json:"name"`
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
		if body.Name != "" {
			updates["name"] = body.Name
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
		invalidateNodesList() // 节点信息变更后失效列表缓存

		var node model.Node
		db.Preload("Capability").Where("id = ?", id).First(&node)
		c.JSON(http.StatusOK, node)
	})

	g.DELETE("/:id", func(c *gin.Context) {
		id := c.Param("id")
		// 在线节点：下发注销指令让 Agent 自毁（停 systemd + 删本地文件 + 退出）。
		// 离线节点返回 not connected 错误，忽略；Agent 重连时被拒触发自毁兜底。
		_ = streamSvc.SendDecommission(c.Request.Context(), id, "node deleted by admin")

		err := db.Transaction(func(tx *gorm.DB) error {
			// 级联清理节点关联数据（AuditLog 保留用于审计追溯）
			for _, m := range []any{
				&model.NodeCapability{},
				&model.NodePolicyInstance{},
				&model.Rule{},
				&model.Task{},
				&model.Snapshot{},
				&model.IptablesRule{},
			} {
				if err := tx.Where("node_id = ?", id).Delete(m).Error; err != nil {
					return err
				}
			}
			// Certificate 标记 revoked（不物理删）：保留指纹防 autoReregister 复活，
			// 拒绝旧证书重连，并留存审计痕迹。
			if err := tx.Model(&model.Certificate{}).Where("node_id = ?", id).Update("revoked", true).Error; err != nil {
				return err
			}
			// 物理删除节点本身
			return tx.Where("id = ?", id).Delete(&model.Node{}).Error
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		invalidateNodesList() // 节点删除后失效列表缓存
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

// computeNodesList 聚合节点列表(B2 缓存的计算函数):Preload 能力 + 每节点 drift 实例数
// + 当前有效证书过期时间。online 字段不在内,由路由层用 Registry 实时覆盖。
func computeNodesList(db *gorm.DB) (any, error) {
	var nodes []model.Node
	if err := db.Preload("Capability").Find(&nodes).Error; err != nil {
		return nil, err
	}
	// 聚合每节点 drift 实例数(实例参数 vs 模板当前参数),供节点列表角标提示
	var instances []model.NodePolicyInstance
	if err := db.Find(&instances).Error; err != nil {
		return nil, err
	}
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
		if err := db.Where("id IN ?", ids).Find(&tpls).Error; err != nil {
			return nil, err
		}
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
		if err := db.Where("node_id IN ? AND revoked = ?", ids, false).Find(&certs).Error; err != nil {
			return nil, err
		}
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
	return nodes, nil
}
