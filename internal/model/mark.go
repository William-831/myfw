package model

import "time"

// Mark 标记定义:给 iptables MARK 动作的可读命名(如 "dev"=15、"ops"=255),
// 供模板/实例编辑时下拉选择,避免裸填数值。Value 为实际 --set-mark 值,
// 模板/实例的 mark / match_mark 字段存该值(编译时直接用,不存 Mark.ID)。
type Mark struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:64;not null" json:"name"` // 标记名(dev / ops / 业务A)
	Value       uint32    `gorm:"uniqueIndex;not null" json:"value"`         // 标记值(0-4294967295)
	Description string    `gorm:"size:512" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
