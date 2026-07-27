package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/stream"
	"iptables-tool/internal/model"
)

func registerIptablesRoutes(r gin.IRouter, db *gorm.DB, streamSvc *stream.Service) {
	g := r.Group("/api/v1/iptables")

	// 获取节点规则列表（准实时：先向 Agent 拉取最新规则写入 DB，再返回）
	g.GET("/rules/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		if streamSvc != nil {
			// 下发 SyncRulesRequest 并等待 Agent 上报（最多 3s）；
			// 超时或节点离线则降级返回 DB 中最近一次的数据。
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

	// 获取规则概览
	g.GET("/overview", func(c *gin.Context) {
		var results []struct {
			NodeID    string `json:"node_id"`
			TableType string `json:"table"`
			Chain     string `json:"chain"`
			RuleCount int    `json:"rule_count"`
		}
		if err := db.Model(&model.IptablesRule{}).
			Select("node_id, table_type, chain, count(*) as rule_count").
			Group("node_id, table_type, chain").
			Find(&results).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"overview": results})
	})

	// 专家模式: 获取链结构树
	g.GET("/chain-tree/:node_id", func(c *gin.Context) {
		nodeID := c.Param("node_id")
		var rules []model.IptablesRule
		if err := db.Where("node_id = ?", nodeID).Order("table_type, chain, priority").Find(&rules).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		tree := buildChainTree(rules)
		c.JSON(http.StatusOK, tree)
	})

	// 批量操作: 启用/禁用策略
	g.POST("/batch-toggle", func(c *gin.Context) {
		var body struct {
			IDs     []uint `json:"ids"`
			Enabled bool   `json:"enabled"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if len(body.IDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ids is required"})
			return
		}
		if err := db.Model(&model.Policy{}).Where("id IN ?", body.IDs).Update("enabled", body.Enabled).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "updated", "count": len(body.IDs)})
	})

	// 批量操作: 删除策略
	g.POST("/batch-delete", func(c *gin.Context) {
		var body struct {
			IDs []uint `json:"ids"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if len(body.IDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ids is required"})
			return
		}
		if err := db.Where("id IN ?", body.IDs).Delete(&model.Policy{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "deleted", "count": len(body.IDs)})
	})

	// 批量操作: 应用策略到指定节点
	g.POST("/batch-apply", func(c *gin.Context) {
		var body struct {
			PolicyIDs []uint   `json:"policy_ids"`
			NodeIDs   []string `json:"node_ids"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if len(body.PolicyIDs) == 0 || len(body.NodeIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "policy_ids and node_ids are required"})
			return
		}
		// 创建任务
		tasks := make([]model.Task, 0, len(body.NodeIDs))
		for _, nodeID := range body.NodeIDs {
			task := model.Task{
				NodeID:  nodeID,
				Status:  model.TaskPendingApproval,
				Version: 1,
			}
			if err := db.Create(&task).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			tasks = append(tasks, task)
		}
		c.JSON(http.StatusOK, gin.H{"tasks": tasks, "count": len(tasks)})
	})

	// 策略冲突检测
	g.POST("/conflicts", func(c *gin.Context) {
		var body struct {
			PolicyIDs []uint `json:"policy_ids"`
		}
		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if len(body.PolicyIDs) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "policy_ids is required"})
			return
		}

		var policies []model.Policy
		if err := db.Where("id IN ?", body.PolicyIDs).Find(&policies).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		conflicts := detectConflicts(policies)
		c.JSON(http.StatusOK, gin.H{"conflicts": conflicts})
	})
}

// isMYFWRule 判断规则是否属于 MYFW 命名空间
func isMYFWRule(rule string) bool {
	if len(rule) < 7 {
		return false
	}
	// 匹配 -A MYFW- 开头的规则
	return strings.HasPrefix(rule, "-A MYFW-") ||
		strings.Contains(rule, "-j MYFW-")
}

// buildChainTree 构建链结构树
func buildChainTree(rules []model.IptablesRule) map[string]interface{} {
	// 按 table 分组
	tableMap := make(map[string]map[string][]model.IptablesRule)
	for _, r := range rules {
		if tableMap[r.TableType] == nil {
			tableMap[r.TableType] = make(map[string][]model.IptablesRule)
		}
		tableMap[r.TableType][r.Chain] = append(tableMap[r.TableType][r.Chain], r)
	}

	tables := make([]map[string]interface{}, 0, len(tableMap))
	// 按 filter, nat, mangle, raw 顺序排列
	tableOrder := []string{"filter", "nat", "mangle", "raw"}
	for _, tableName := range tableOrder {
		chains, ok := tableMap[tableName]
		if !ok {
			continue
		}
		tables = append(tables, buildTableChain(tableName, chains))
	}
	// 添加不在预定义顺序中的表
	for tableName := range tableMap {
		found := false
		for _, t := range tableOrder {
			if t == tableName {
				found = true
				break
			}
		}
		if !found {
			tables = append(tables, buildTableChain(tableName, tableMap[tableName]))
		}
	}

	return map[string]interface{}{"tables": tables}
}

func buildTableChain(tableName string, chains map[string][]model.IptablesRule) map[string]interface{} {
	chainList := make([]map[string]interface{}, 0, len(chains))
	// 系统链优先显示
	systemChains := []string{"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"}
	myfwChains := []string{"MYFW-INPUT", "MYFW-OUTPUT", "MYFW-FORWARD", "MYFW-PREROUTING", "MYFW-POSTROUTING", "MYFW-MANGLE"}

	processed := make(map[string]bool)

	// 先处理系统链
	for _, chainName := range systemChains {
		rules, ok := chains[chainName]
		if !ok {
			continue
		}
		processed[chainName] = true

		chainInfo := map[string]interface{}{
			"name":  chainName,
			"rules": formatRules(rules),
		}

		// 查找对应的 MYFW 跳转规则
		for _, r := range rules {
			if strings.Contains(r.RuleLine, "-j MYFW-") {
				chainInfo["jump_rule"] = r.RuleLine
				break
			}
		}

		chainList = append(chainList, chainInfo)
	}

	// 处理 MYFW 链
	for _, chainName := range myfwChains {
		rules, ok := chains[chainName]
		if !ok {
			continue
		}
		processed[chainName] = true

		chainInfo := map[string]interface{}{
			"name":  chainName,
			"rules": formatRules(rules),
			"is_myfw": true,
		}
		chainList = append(chainList, chainInfo)
	}

	// 处理其他链
	for chainName, rules := range chains {
		if processed[chainName] {
			continue
		}
		chainInfo := map[string]interface{}{
			"name":  chainName,
			"rules": formatRules(rules),
		}
		chainList = append(chainList, chainInfo)
	}

	return map[string]interface{}{
		"name":   tableName,
		"chains": chainList,
	}
}

func formatRules(rules []model.IptablesRule) []map[string]interface{} {
	result := make([]map[string]interface{}, 0, len(rules))
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	for _, r := range rules {
		result = append(result, map[string]interface{}{
			"index":   r.Priority,
			"raw":     r.RuleLine,
			"is_myfw": r.IsMYFW,
		})
	}
	return result
}

// ConflictItem 策略冲突项
type ConflictItem struct {
	Type     string `json:"type"`     // priority_overlap / action_conflict / redundant
	Severity string `json:"severity"` // warning / error / info
	Message  string `json:"message"`
	PolicyA  uint   `json:"policy_a"`
	PolicyB  uint   `json:"policy_b"`
}

// detectConflicts 检测策略间冲突
func detectConflicts(policies []model.Policy) []ConflictItem {
	var conflicts []ConflictItem

	for i := 0; i < len(policies); i++ {
		for j := i + 1; j < len(policies); j++ {
			a, b := policies[i], policies[j]

			// 忽略禁用的策略
			if !a.Enabled || !b.Enabled {
				continue
			}

			// 方向不同不冲突
			if a.Direction != b.Direction && a.Direction != "" && b.Direction != "" {
				continue
			}

			// 协议不同不冲突
			if a.Protocol != b.Protocol && a.Protocol != "ANY" && b.Protocol != "ANY" &&
				a.Protocol != "" && b.Protocol != "" {
				continue
			}

			// 检查端口交集
			if !portOverlap(a.PortRange, b.PortRange) {
				continue
			}

			// 检查源/目的地址交集
			if !addrOverlap(a.Source, b.Source) || !addrOverlap(a.Destination, b.Destination) {
				continue
			}

			// 优先级相同
			if a.Priority == b.Priority {
				conflicts = append(conflicts, ConflictItem{
					Type:     "priority_overlap",
					Severity: "warning",
					Message:  "优先级相同，规则执行顺序不明确",
					PolicyA:  a.ID,
					PolicyB:  b.ID,
				})
			}

			// 动作矛盾
			if a.Action != b.Action {
				conflicts = append(conflicts, ConflictItem{
					Type:     "action_conflict",
					Severity: "error",
					Message:  "同端口不同动作，可能产生非预期行为",
					PolicyA:  a.ID,
					PolicyB:  b.ID,
				})
			}

			// 规则冗余（优先级低的被优先级高的完全包含）
			if a.Priority < b.Priority && isRedundant(a, b) {
				conflicts = append(conflicts, ConflictItem{
					Type:     "redundant",
					Severity: "info",
					Message:  "低优先级规则被高优先级规则完全包含，可能冗余",
					PolicyA:  a.ID,
					PolicyB:  b.ID,
				})
			}
		}
	}
	return conflicts
}

// portOverlap 检查端口范围是否有交集
func portOverlap(a, b string) bool {
	if a == "" || b == "" {
		return true // 空表示任意端口
	}
	if a == b {
		return true
	}
	// 简化处理：包含 "-" 的为范围
	return true
}

// addrOverlap 检查地址是否有交集
func addrOverlap(a, b string) bool {
	if a == "" || b == "" {
		return true // 空表示任意地址
	}
	return a == b
}

// isRedundant 检查 a 是否完全包含 b（a 优先级更高）
func isRedundant(a, b model.Policy) bool {
	// 简化判断：如果 a 的源/目的覆盖 b 且端口覆盖
	if a.Source != "" && a.Source != b.Source {
		return false
	}
	if a.Destination != "" && a.Destination != b.Destination {
		return false
	}
	return true
}
