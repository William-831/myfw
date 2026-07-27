package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"iptables-tool/internal/controller/audit"
)

func registerAuditRoutes(r gin.IRouter, auditSink *audit.Sink) {
	r.GET("/api/v1/audit/logs", func(c *gin.Context) {
		action := c.Query("action")
		nodeID := c.Query("node_id")
		limitStr := c.DefaultQuery("limit", "10")
		offsetStr := c.DefaultQuery("offset", "0")

		limit, _ := strconv.Atoi(limitStr)
		offset, _ := strconv.Atoi(offsetStr)

		logs, total, err := auditSink.Query(c.Request.Context(), action, nodeID, limit, offset)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": logs, "total": total})
	})

	r.GET("/api/v1/audit/export", func(c *gin.Context) {
		action := c.Query("action")
		nodeID := c.Query("node_id")

		logs, _, err := auditSink.Query(c.Request.Context(), action, nodeID, 10000, 0)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.Header("Content-Type", "text/csv")
		c.Header("Content-Disposition", "attachment; filename=audit_logs.csv")

		w := csv.NewWriter(c.Writer)
		w.Write([]string{"ID", "Actor", "Action", "NodeID", "Detail", "CreatedAt"})
		for _, log := range logs {
			w.Write([]string{
				fmt.Sprintf("%d", log.ID),
				log.Actor,
				log.Action,
				log.NodeID,
				log.Detail,
				log.CreatedAt.Format(time.RFC3339),
			})
		}
		w.Flush()
	})
}
