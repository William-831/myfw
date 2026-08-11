package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/model"
)

// registerCustomChainRoutes 挂载策略组(自定义子链)的 CRUD 接口。策略组=自定义子链
// MYFW-<name>,可多挂载(一条链被多个父链各 jump 一次,多钩子 P1b);
// 条目(模板/实例)通过 group_id 归属链(组即落点),规则落于链。
func registerCustomChainRoutes(r gin.IRouter, db *gorm.DB, auditSink *audit.Sink) {
	g := r.Group("/api/v1/custom-chains")
	g.GET("", listCustomChains(db))
	g.POST("", createCustomChain(db, auditSink))
	g.GET("/:id", getCustomChain(db))
	g.PUT("/:id", updateCustomChain(db, auditSink))
	g.DELETE("/:id", deleteCustomChain(db, auditSink))
}

// customChainInput 策略组(自定义子链)写入入参。
// Mounts 为权威挂载列表(多钩子);Parent/Priority 为兼容字段(旧前端/旧数据回退)。
type customChainInput struct {
	Name        string             `json:"name"`
	Parent      string             `json:"parent"`   // 兼容:主挂载父链(Mounts 镜像)
	Table       string             `json:"table"`
	Priority    int                `json:"priority"` // 兼容:主挂载优先级(Mounts 镜像)
	Mounts      []model.ChainMount `json:"mounts"`   // 权威挂载列表,空则回退 Parent/Priority
	Description string             `json:"description"`
	Enabled     bool               `json:"enabled"`
}

// chainView 列表/详情视图:在 model 基础上补解析后的挂载列表(前端直接消费,无需解析 JSON)。
type chainView struct {
	model.CustomChain
	MountList []model.ChainMount `json:"mount_list"`
}

func toChainView(ch model.CustomChain) chainView {
	return chainView{CustomChain: ch, MountList: ch.MountList()}
}

// validChainParents 父链白名单:父链 -> 所属表。
var validChainParents = map[string]string{
	"MYFW-INPUT":       "filter",
	"MYFW-OUTPUT":      "filter",
	"MYFW-FORWARD":     "filter",
	"MYFW-PREROUTING":  "nat",
	"MYFW-POSTROUTING": "nat",
	"MYFW-MANGLE":      "mangle",
}

func listCustomChains(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var chains []model.CustomChain
		if err := db.Order("priority ASC, id ASC").Find(&chains).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		out := make([]chainView, len(chains))
		for i := range chains {
			out[i] = toChainView(chains[i])
		}
		c.JSON(http.StatusOK, gin.H{"custom_chains": out})
	}
}

func createCustomChain(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in customChainInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateCustomChainInput(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		ch := model.CustomChain{
			Name: in.Name, Table: in.Table,
			Description: in.Description, Enabled: in.Enabled,
		}
		applyMountsToChain(&ch, &in)
		if err := db.Create(&ch).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditChain(auditSink, c, "create", ch.ID, ch.Name, nil)
		c.JSON(http.StatusCreated, toChainView(ch))
	}
}

func getCustomChain(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch, ok := loadCustomChain(c, db)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, toChainView(*ch))
	}
}

func updateCustomChain(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch, ok := loadCustomChain(c, db)
		if !ok {
			return
		}
		var in customChainInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateCustomChainInput(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		oldEnabled := ch.Enabled
		ch.Name = in.Name
		ch.Table = in.Table
		ch.Description = in.Description
		ch.Enabled = in.Enabled
		applyMountsToChain(ch, &in)
		if err := db.Save(ch).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// P2 生命周期显式化:禁用链时审计,detail 含受影响实例数(组链/落点链引用),
		// 不再"禁用组=其下实例静默失效"而无感知。
		extra := map[string]any{"enabled": ch.Enabled}
		if oldEnabled && !ch.Enabled {
			extra["affected_instances"] = chainReferencedInstances(db, ch.ID)
			auditChain(auditSink, c, "disabled", ch.ID, ch.Name, extra)
		} else {
			auditChain(auditSink, c, "update", ch.ID, ch.Name, extra)
		}
		c.JSON(http.StatusOK, toChainView(*ch))
	}
}

func deleteCustomChain(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch, ok := loadCustomChain(c, db)
		if !ok {
			return
		}
		// 引用检查:策略(group_id)/模板/实例(group_id)引用本链则拒绝删除
		var count int64
		db.Model(&model.Policy{}).Where("group_id = ?", ch.ID).Count(&count)
		if count == 0 {
			db.Model(&model.PolicyTemplate{}).Where("group_id = ?", ch.ID).Count(&count)
		}
		if count == 0 {
			db.Model(&model.NodePolicyInstance{}).Where("group_id = ?", ch.ID).Count(&count)
		}
		if count > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("自定义链被 %d 条策略/模板/实例引用,请先移除引用后再删除", count)})
			return
		}
		if err := db.Delete(ch).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditChain(auditSink, c, "delete", ch.ID, ch.Name, nil)
		c.Status(http.StatusNoContent)
	}
}

// loadCustomChain 按 :id 加载,失败时已写响应,返回 ok=false。
func loadCustomChain(c *gin.Context, db *gorm.DB) (*model.CustomChain, bool) {
	id := c.Param("id")
	var ch model.CustomChain
	if err := db.Where("id = ?", id).First(&ch).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "custom chain not found"})
		return nil, false
	}
	return &ch, true
}

// validateCustomChainInput 校验 name、挂载点 parent(白名单)与 table 一致性。
// Mounts 优先;空则回退 Parent/Priority(旧前端/旧数据单挂载兼容)。
func validateCustomChainInput(in *customChainInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("custom chain: name is required")
	}
	mounts := in.Mounts
	if len(mounts) == 0 {
		mounts = []model.ChainMount{{Parent: in.Parent, Priority: in.Priority}}
	}
	for _, m := range mounts {
		table, ok := validChainParents[m.Parent]
		if !ok {
			return errors.New("custom chain: parent must be MYFW-INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING/MANGLE")
		}
		if in.Table != table {
			return errors.New("custom chain: table must match parent (" + table + ")")
		}
	}
	return nil
}

// applyMountsToChain 写挂载列表(Mounts 权威)+ 同步 Parent/Priority(兼容字段镜像)。
// 旧前端只传 Parent/Priority 时 Mounts 留空,读取回退单挂载(存量兼容)。
func applyMountsToChain(ch *model.CustomChain, in *customChainInput) {
	if len(in.Mounts) > 0 {
		b, _ := json.Marshal(in.Mounts)
		ch.Mounts = string(b)
		ch.Parent, ch.Priority = in.Mounts[0].Parent, in.Mounts[0].Priority
		return
	}
	ch.Mounts = ""
	ch.Parent, ch.Priority = in.Parent, in.Priority
}

// auditChain 写自定义链审计(create/update/disabled/delete)。
func auditChain(auditSink *audit.Sink, c *gin.Context, op string, id uint, name string, extra map[string]any) {
	if auditSink == nil {
		return
	}
	detail := map[string]any{"op": op, "chain_id": id, "name": name}
	for k, v := range extra {
		detail[k] = v
	}
	buf, _ := json.Marshal(detail)
	_ = auditSink.Write(c.Request.Context(), model.AuditLog{
		Actor:  actor(c),
		Action: "chain." + op,
		Detail: string(buf),
	})
}

// chainReferencedInstances 统计引用该链的实例数(组链 GroupID)。
// 供禁用链审计 detail 展示受影响实例数(P2)。
func chainReferencedInstances(db *gorm.DB, chainID uint) int64 {
	var n int64
	db.Model(&model.NodePolicyInstance{}).
		Where("group_id = ?", chainID).
		Count(&n)
	return n
}
