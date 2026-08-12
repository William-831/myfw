package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/model"
)

func registerIptablesRoutes(r gin.IRouter, db *gorm.DB, streamSvc *stream.Service, comp *compiler.Compiler, auditSink *audit.Sink) {
	g := r.Group("/api/v1/iptables")

	// 获取节点规则列表（准实时：先向 Agent 拉取最新规则写入 DB，再返回）
	g.GET("/rules/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		if streamSvc != nil {
			_ = streamSvc.RequestRulesAndWait(c.Request.Context(), nodeID, 3*time.Second)
		}
		var rules []model.IptablesRule
		if err := db.Where("node_id = ?", nodeID).Order("table_type, chain, priority").Find(&rules).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"rules": rules})
	})

	// 下发单条规则操作（增删改插，双模式），等待 Agent 执行结果
	g.POST("/rules/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var op myfwv1.RuleOperation
		if err := c.ShouldBindJSON(&op); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if op.TaskId == "" {
			op.TaskId = fmt.Sprintf("ruleop-%d", time.Now().UnixNano())
		}
		if streamSvc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "stream service unavailable"})
			return
		}
		res, err := streamSvc.SendRuleOperation(c.Request.Context(), nodeID, &op, 5*time.Second)
		if err != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"result": res})
	})

	// 策略漂移检测：对比策略编译期望态 vs 节点真实 MYFW 规则
	g.GET("/drift/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		expected, _, _, err := comp.CompileForNode(c.Request.Context(), nodeID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var actual []model.IptablesRule
		db.Where("node_id = ? AND is_myfw = ?", nodeID, true).Order("table_type, chain, priority").Find(&actual)
		expectedCount := len(expected)
		actualCount := len(actual)
		c.JSON(http.StatusOK, gin.H{
			"expected":       expected,
			"actual":         actual,
			"expected_count": expectedCount,
			"actual_count":   actualCount,
			"drifted":        expectedCount != actualCount,
		})
	})

	// Agent 上报规则
	g.POST("/report/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var body struct {
			Chains []struct {
				Table string   `json:"table"`
				Chain string   `json:"chain"`
				Rules []string `json:"rules"`
			} `json:"chains"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		tx := db.Begin()
		defer func() {
			if r := recover(); r != nil {
				tx.Rollback()
			}
		}()

		if err := tx.Where("node_id = ?", nodeID).Delete(&model.IptablesRule{}).Error; err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		for _, chain := range body.Chains {
			for i, rule := range chain.Rules {
				isMYFW := isMYFWRule(rule)
				iptablesRule := model.IptablesRule{
					NodeID:    nodeID,
					TableType: chain.Table,
					Chain:     chain.Chain,
					RuleLine:  rule,
					Priority:  i,
					IsMYFW:    isMYFW,
				}
				if err := tx.Create(&iptablesRule).Error; err != nil {
					tx.Rollback()
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}
		}

		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "rules updated"})
	})

	// Agent 上报 MYFW 规则命中率(pkts/bytes + comment 反解实例 ID)。
	// 同实例多条规则按 max 聚合,按 (node,instance) upsert RuleHitStat。
	// 规则活性分析:Controller 据此标记死规则(启用且 packets=0 且超阈值)。
	g.POST("/hits/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var body struct {
			Hits []struct {
				InstanceID uint  `json:"instance_id"`
				Packets    int64 `json:"packets"`
				Bytes      int64 `json:"bytes"`
			} `json:"hits"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// 按 instance_id 聚合 max(同实例多条规则:主规则+acl+drop,取最大代表是否有流量命中)
		agg := map[uint]model.RuleHitStat{}
		for _, h := range body.Hits {
			if h.InstanceID == 0 {
				continue
			}
			cur, ok := agg[h.InstanceID]
			if !ok {
				cur = model.RuleHitStat{InstanceID: h.InstanceID, Packets: h.Packets, Bytes: h.Bytes}
			} else {
				if h.Packets > cur.Packets {
					cur.Packets = h.Packets
				}
				if h.Bytes > cur.Bytes {
					cur.Bytes = h.Bytes
				}
			}
			agg[h.InstanceID] = cur
		}
		now := time.Now()
		tx := db.Begin()
		for _, st := range agg {
			st.NodeID = nodeID
			st.LastSeen = now
			var existing model.RuleHitStat
			if err := tx.Where("node_id = ? AND instance_id = ?", nodeID, st.InstanceID).First(&existing).Error; err != nil {
				// 不存在 -> 创建
				if err := tx.Create(&st).Error; err != nil {
					tx.Rollback()
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			} else {
				// 存在 -> 更新计数器
				existing.Packets = st.Packets
				existing.Bytes = st.Bytes
				existing.LastSeen = now
				if err := tx.Save(&existing).Error; err != nil {
					tx.Rollback()
					c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
					return
				}
			}
		}
		if err := tx.Commit().Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "hits updated"})
	})

	// 查询节点规则命中率 + 死规则判定。
	// dead = enabled=true + 有 RuleHitStat(采集过) + packets=0 + created_at 超阈值(默认 7 天)。
	// 无 RuleHitStat 的实例 packets=0 但 dead=false(数据不足,可能尚未采集)。
	g.GET("/rule-hits/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var instances []model.NodePolicyInstance
		if err := db.Where("node_id = ?", nodeID).Find(&instances).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		var stats []model.RuleHitStat
		db.Where("node_id = ?", nodeID).Find(&stats)
		statByID := map[uint]model.RuleHitStat{}
		for i := range stats {
			statByID[stats[i].InstanceID] = stats[i]
		}
		threshold := time.Now().Add(-deadRuleThresholdDays * 24 * time.Hour)
		type hitVO struct {
			InstanceID uint       `json:"instance_id"`
			Name       string     `json:"name"`
			Enabled    bool       `json:"enabled"`
			Packets    int64      `json:"packets"`
			Bytes      int64      `json:"bytes"`
			LastSeen   *time.Time `json:"last_seen"`
			Dead       bool       `json:"dead"`
		}
		out := make([]hitVO, 0, len(instances))
		for _, inst := range instances {
			st, hasStat := statByID[inst.ID]
			dead := inst.Enabled && hasStat && st.Packets == 0 && inst.CreatedAt.Before(threshold)
			vo := hitVO{
				InstanceID: inst.ID,
				Name:       inst.Name,
				Enabled:    inst.Enabled,
				Dead:       dead,
			}
			if hasStat {
				vo.Packets = st.Packets
				vo.Bytes = st.Bytes
				vo.LastSeen = &st.LastSeen
			}
			out = append(out, vo)
		}
		c.JSON(http.StatusOK, gin.H{"hits": out})
	})

	// 专家模式:执行裸 iptables 命令(iptables 族白名单校验在 Agent 侧),同步等待回复。
	// 此通道绕过 MYFW 命名空间/快照/保护期,强审计记录操作人/节点/命令/输出。
	g.POST("/exec/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var body struct {
			Command string `json:"command"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if strings.TrimSpace(body.Command) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "command is required"})
			return
		}
		if streamSvc == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "stream service unavailable"})
			return
		}
		res, err := streamSvc.SendExecAndWait(c.Request.Context(), nodeID, body.Command, 10*time.Second)
		if err != nil {
			c.JSON(http.StatusGatewayTimeout, gin.H{"error": err.Error()})
			return
		}
		// 强审计:专家终端绕过保护期,记录操作人/节点/命令/输出 + scene=expert_bypass,便于事后追溯
		if auditSink != nil {
			result := model.AuditResultSuccess
			if !res.Ok {
				result = model.AuditResultFailed
			}
			detail, _ := json.Marshal(map[string]any{
				"scene":   model.AuditSceneExpertBypass,
				"command": body.Command,
				"ok":      res.Ok,
				"output":  res.Message,
			})
			_ = auditSink.Write(c.Request.Context(), model.AuditLog{
				Actor:  actor(c),
				Action: "iptables.exec",
				Scene:  model.AuditSceneExpertBypass,
				Result: result,
				NodeID: nodeID,
				Detail: string(detail),
			})
		}
		c.JSON(http.StatusOK, gin.H{"ok": res.Ok, "output": res.Message})
	})
}

// isMYFWRule 判断规则是否属于 MYFW 命名空间
func isMYFWRule(rule string) bool {
	if len(rule) < 7 {
		return false
	}
	return strings.HasPrefix(rule, "-A MYFW-") ||
		strings.Contains(rule, "-j MYFW-")
}

// deadRuleThresholdDays 死规则判定阈值:实例启用且 packets=0 且创建超此天数 -> dead。
// 首版硬编码 7 天;后续需要可配置化时迁移到 SystemSetting。
const deadRuleThresholdDays = 7
