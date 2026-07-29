package server

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// registerAddressGroupRoutes 挂载地址组(白/黑名单 IP 段集合)的 CRUD 接口。
// 地址组编译期绑定到节点上的 ipset / nft set,Policy 通过 SourceGroup 引用其名称。
func registerAddressGroupRoutes(r gin.IRouter, db *gorm.DB) {
	g := r.Group("/api/v1/address-groups")
	g.GET("", listAddressGroups(db))
	g.POST("", createAddressGroup(db))
	g.GET("/:id", getAddressGroup(db))
	g.PUT("/:id", updateAddressGroup(db))
	g.DELETE("/:id", deleteAddressGroup(db))
}

// addressGroupInput 地址组写入入参,members 为 CIDR 字符串数组。
type addressGroupInput struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"` // whitelist | blacklist | custom
	Members     []string `json:"members"`
	Description string   `json:"description"`
}

func listAddressGroups(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var groups []model.AddressGroup
		if err := db.Order("kind ASC, name ASC").Find(&groups).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		out := make([]map[string]any, 0, len(groups))
		for i := range groups {
			out = append(out, addressGroupToMap(groups[i]))
		}
		c.JSON(http.StatusOK, gin.H{"address_groups": out})
	}
}

func createAddressGroup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in addressGroupInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateAddressGroupInput(in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		membersJSON, _ := json.Marshal(in.Members)
		g := model.AddressGroup{
			Name:        in.Name,
			Kind:        in.Kind,
			Members:     string(membersJSON),
			Description: in.Description,
		}
		if err := db.Create(&g).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, addressGroupToMap(g))
	}
}

func getAddressGroup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		g, ok := loadAddressGroup(c, db)
		if !ok {
			return
		}
		c.JSON(http.StatusOK, addressGroupToMap(*g))
	}
}

func updateAddressGroup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		g, ok := loadAddressGroup(c, db)
		if !ok {
			return
		}
		var in addressGroupInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateAddressGroupInput(in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		membersJSON, _ := json.Marshal(in.Members)
		g.Name = in.Name
		g.Kind = in.Kind
		g.Members = string(membersJSON)
		g.Description = in.Description
		if err := db.Save(g).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, addressGroupToMap(*g))
	}
}

func deleteAddressGroup(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		g, ok := loadAddressGroup(c, db)
		if !ok {
			return
		}
		if err := db.Delete(g).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Status(http.StatusNoContent)
	}
}

// loadAddressGroup 按 :id 加载,失败时已写响应,返回 ok=false。
func loadAddressGroup(c *gin.Context, db *gorm.DB) (*model.AddressGroup, bool) {
	id := c.Param("id")
	var g model.AddressGroup
	if err := db.Where("id = ?", id).First(&g).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "address group not found"})
		return nil, false
	}
	return &g, true
}

// addressGroupToMap 把 Members JSON 还原为数组,前端无需二次解析。
func addressGroupToMap(g model.AddressGroup) map[string]any {
	var members []string
	if g.Members != "" {
		_ = json.Unmarshal([]byte(g.Members), &members)
	}
	return map[string]any{
		"id":          g.ID,
		"name":        g.Name,
		"kind":        g.Kind,
		"members":     members,
		"description": g.Description,
		"created_at":  g.CreatedAt,
		"updated_at":  g.UpdatedAt,
	}
}

// validateAddressGroupInput 校验名称、类型与每个 CIDR 格式。
func validateAddressGroupInput(in addressGroupInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return errors.New("address group: name is required")
	}
	switch in.Kind {
	case "whitelist", "blacklist", "custom":
	default:
		return errors.New("address group: kind must be whitelist/blacklist/custom")
	}
	for _, m := range in.Members {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(m)); err != nil {
			return errors.New("address group: invalid CIDR: " + m)
		}
	}
	return nil
}
