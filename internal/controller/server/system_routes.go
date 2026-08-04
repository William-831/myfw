package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// registerSystemRoutes 系统设置:日志/审批保留天数 + 手动清理异常数据。
func registerSystemRoutes(r gin.IRouter, db *gorm.DB) {
	g := r.Group("/api/v1/system")
	g.GET("/retention", getRetention(db))
	g.PUT("/retention", updateRetention(db))
	g.POST("/cleanup", cleanupNow(db))
}

func getRetention(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"audit_retention_days": getSettingInt(db, model.SettingAuditRetentionDays, model.DefaultAuditRetentionDays),
			"task_retention_days":  getSettingInt(db, model.SettingTaskRetentionDays, model.DefaultTaskRetentionDays),
		})
	}
}

func updateRetention(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var in struct {
			AuditRetentionDays int `json:"audit_retention_days"`
			TaskRetentionDays  int `json:"task_retention_days"`
		}
		if err := c.ShouldBindJSON(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if in.AuditRetentionDays < 1 {
			in.AuditRetentionDays = 1
		}
		if in.TaskRetentionDays < 1 {
			in.TaskRetentionDays = 1
		}
		setSetting(db, model.SettingAuditRetentionDays, strconv.Itoa(in.AuditRetentionDays))
		setSetting(db, model.SettingTaskRetentionDays, strconv.Itoa(in.TaskRetentionDays))
		c.JSON(http.StatusOK, gin.H{"audit_retention_days": in.AuditRetentionDays, "task_retention_days": in.TaskRetentionDays})
	}
}

// cleanupNow 手动清理异常数据:卡死的 task(applying/dispatching 超 1h)+ 超时待审批 +
// 已完成超保留期的 task + 超保留期的审计日志。返回各分类删除数。
func cleanupNow(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, runCleanup(db))
	}
}

func getSettingInt(db *gorm.DB, key, def string) int {
	var s model.SystemSetting
	if err := db.Where("key = ?", key).First(&s).Error; err != nil {
		return atoi(def)
	}
	return atoi(s.Value)
}
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	if n < 1 {
		n = 1
	}
	return n
}
func setSetting(db *gorm.DB, key, value string) {
	db.Save(&model.SystemSetting{Key: key, Value: value, UpdatedAt: time.Now()})
}

// runCleanup 执行清理,返回各表删除数。
func runCleanup(db *gorm.DB) map[string]int {
	auditDays := getSettingInt(db, model.SettingAuditRetentionDays, model.DefaultAuditRetentionDays)
	taskDays := getSettingInt(db, model.SettingTaskRetentionDays, model.DefaultTaskRetentionDays)
	now := time.Now()
	taskCutoff := now.AddDate(0, 0, -taskDays)
	auditCutoff := now.AddDate(0, 0, -auditDays)
	stuckCutoff := now.Add(-time.Hour) // 1 小时未推进视为卡死

	res := map[string]int{}
	d := db.Where("status IN ? AND updated_at < ?", []string{"applying", "dispatching"}, stuckCutoff).Delete(&model.Task{})
	res["stuck_tasks"] = int(d.RowsAffected)
	d = db.Where("status = ? AND created_at < ?", "pending_approval", now.Add(-24*time.Hour)).Delete(&model.Task{})
	res["timeout_pending_tasks"] = int(d.RowsAffected)
	d = db.Where("status IN ? AND created_at < ?", []string{"confirmed", "rolled_back", "failed"}, taskCutoff).Delete(&model.Task{})
	res["expired_tasks"] = int(d.RowsAffected)
	d = db.Where("created_at < ?", auditCutoff).Delete(&model.AuditLog{})
	res["expired_audit_logs"] = int(d.RowsAffected)
	return res
}

// StartRetentionLoop 定时清理 goroutine:每天执行一次 runCleanup,释放空间。
func StartRetentionLoop(db *gorm.DB, log func(msg string, args ...any)) {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			res := runCleanup(db)
			if log != nil {
				log("retention cleanup", "result", fmt.Sprintf("%v", res))
			}
		}
	}()
}
