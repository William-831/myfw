package model

import "time"

// CustomChain 用户自定义子链:子链 MYFW-<name> 从父链(MYFW-INPUT/FORWARD/...)
// jump 进来。Policy 通过 Chain 字段指定规则落到子链,用于规则按业务归类。
type CustomChain struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:64;not null" json:"name"` // 子链名(MYFW-<name>)
	Parent      string    `gorm:"size:32;not null" json:"parent"`           // 父链 MYFW-INPUT/FORWARD/OUTPUT/PREROUTING/POSTROUTING/MANGLE
	Table       string    `gorm:"size:16;not null" json:"table"`            // 表 filter/nat/mangle,与父链一致
	Priority    int       `gorm:"index;default:50" json:"priority"`         // 全局调度顺序:父链中 jump 到本子链的顺序,值小排前
	Description string    `gorm:"size:512" json:"description"`
	Enabled     bool      `gorm:"index" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
