package model

import "time"

// SystemSetting 系统设置(key-value),存日志/审批保留天数等可配项。
// 用 key-value 而非列式,便于后续扩展新设置项无需迁移。
type SystemSetting struct {
	Key       string    `gorm:"primaryKey;size:64" json:"key"`
	Value     string    `gorm:"size:255" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// 保留设置默认值:日志 30 天,审批(已完成任务)7 天
const (
	SettingAuditRetentionDays = "audit_retention_days"
	SettingTaskRetentionDays  = "task_retention_days"
	DefaultAuditRetentionDays = "30"
	DefaultTaskRetentionDays  = "7"
)
