package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/controller/audit"
	"iptables-tool/internal/model"
)

// registerMarkRoutes 挂载标记定义的 CRUD 接口。标记给 MARK 动作的可读命名
// (name->value),供模板/实例编辑下拉选择,避免裸填数值。
func registerMarkRoutes(r gin.IRouter, db *gorm.DB, auditSink *audit.Sink) {
	g := r.Group("/api/v1/marks")
	g.GET("", listMarks(db))
	g.POST("", createMark(db, auditSink))
	g.GET("/:id", getMark(db))
	g.PUT("/:id", updateMark(db, auditSink))
	g.DELETE("/:id", deleteMark(db, auditSink))
}

type markInput struct {
	Name        string `json:"name"`
	Value       uint32 `json:"value"`
	Description string `json:"description"`
}

func listMarks(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var marks []model.Mark
		if err := db.Order("value ASC").Find(&marks).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"marks": marks})
	}
}

func createMark(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in markInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateMarkInput(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		m := model.Mark{Name: in.Name, Value: in.Value, Description: in.Description}
		if err := db.Create(&m).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		auditMark(auditSink, c, "create", m.ID, m.Name)
		c.JSON(http.StatusCreated, m)
	}
}

func getMark(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := parseMarkID(c)
		if !ok {
			return
		}
		var m model.Mark
		if err := db.First(&m, id).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "mark not found"})
			return
		}
		c.JSON(http.StatusOK, m)
	}
}

func updateMark(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := parseMarkID(c)
		if !ok {
			return
		}
		var in markInput
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := validateMarkInput(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Model(&model.Mark{}).Where("id = ?", id).Updates(map[string]any{
			"name": in.Name, "value": in.Value, "description": in.Description,
		}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditMark(auditSink, c, "update", id, in.Name)
		c.JSON(http.StatusOK, gin.H{"id": id, "name": in.Name, "value": in.Value, "description": in.Description})
	}
}

func deleteMark(db *gorm.DB, auditSink *audit.Sink) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, ok := parseMarkID(c)
		if !ok {
			return
		}
		var m model.Mark
		db.First(&m, id)
		if err := db.Delete(&model.Mark{}, id).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		auditMark(auditSink, c, "delete", id, m.Name)
		c.Status(http.StatusNoContent)
	}
}

func parseMarkID(c *gin.Context) (uint, bool) {
	n, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil || n == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad id"})
		return 0, false
	}
	return uint(n), true
}

func validateMarkInput(in *markInput) error {
	if in.Name == "" {
		return errors.New("mark: name is required")
	}
	return nil
}

func auditMark(auditSink *audit.Sink, c *gin.Context, op string, id uint, name string) {
	if auditSink == nil {
		return
	}
	detail, _ := json.Marshal(map[string]any{"op": op, "mark_id": id, "name": name})
	_ = auditSink.Write(c.Request.Context(), model.AuditLog{
		Actor:  actor(c),
		Action: "mark." + op,
		Detail: string(detail),
	})
}
