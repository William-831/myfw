package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// registerCustomChainRoutes 挂载自定义子链的 CRUD 接口。子链 MYFW-<name> 从父链
// jump 进来,Policy 通过 chain 字段引用其名称,用于规则按业务归类。
func registerCustomChainRoutes(r gin.IRouter, db *gorm.DB) {
	g := r.Group("/api/v1/custom-chains")
	g.GET("", listCustomChains(db))
	g.POST("", createCustomChain(db))
	g.GET("/:id", getCustomChain(db))
	g.PUT("/:id", updateCustomChain(db))
	g.DELETE("/:id", deleteCustomChain(db))
}

// customChainInput 自定义子链写入入参。
type customChainInput struct {
	Name        string `json:"name"`        // 子链名(不带 MYFW- 前缀,节点链 MYFW-<name>)
	Parent      string `json:"parent"`      // 父链 MYFW-INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING/MANGLE
	Table       string `json:"table"`       // 表 filter/nat/mangle,须与父链一致
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
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
		if err := db.Order("name ASC").Find(&chains).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"custom_chains": chains})
	}
}

func createCustomChain(db *gorm.DB) gin.HandlerFunc {
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
			Name: in.Name, Parent: in.Parent, Table: in.Table,
			Description: in.Description, Enabled: in.Enabled,
		}
		if err := db.Create(&ch).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, ch)
	}
}

func getCustomChain(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch, ok := loadCustomChain(c, db)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, ch)
	}
}

func updateCustomChain(db *gorm.DB) gin.HandlerFunc {
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
		ch.Name = in.Name
		ch.Parent = in.Parent
		ch.Table = in.Table
		ch.Description = in.Description
		ch.Enabled = in.Enabled
		if err := db.Save(ch).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, ch)
	}
}

func deleteCustomChain(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch, ok := loadCustomChain(c, db)
		if !ok {
			return
		}
		if err := db.Delete(ch).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
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

// validateCustomChainInput 校验 name、parent(白名单)、table(与父链一致)。
func validateCustomChainInput(in *customChainInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("custom chain: name is required")
	}
	table, ok := validChainParents[in.Parent]
	if !ok {
		return errors.New("custom chain: parent must be MYFW-INPUT/OUTPUT/FORWARD/PREROUTING/POSTROUTING/MANGLE")
	}
	if in.Table != table {
		return errors.New("custom chain: table must match parent (" + table + ")")
	}
	return nil
}
