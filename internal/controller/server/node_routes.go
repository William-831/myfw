package server

import (
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

func registerNodeRoutes(r gin.IRouter, db *gorm.DB) {
	g := r.Group("/api/v1/nodes")

	g.GET("/list", func(c *gin.Context) {
		var nodes []model.Node
		if err := db.Preload("Capability").Find(&nodes).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
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
}
