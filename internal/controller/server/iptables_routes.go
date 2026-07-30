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
		// 强审计:记录操作人/节点/命令/输出,便于事后追溯
		if auditSink != nil {
			detail, _ := json.Marshal(map[string]any{
				"command": body.Command,
				"ok":      res.Ok,
				"output":  res.Message,
			})
			_ = auditSink.Write(c.Request.Context(), model.AuditLog{
				Actor:  actor(c),
				Action: "iptables.exec",
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
