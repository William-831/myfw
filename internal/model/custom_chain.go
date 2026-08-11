package model

import (
	"encoding/json"
	"time"
)

// ChainMount 链挂载点:钩子父链 + 该父链中 jump 优先级(值小排前)。
// 一条链可有多个挂载(P1b 多钩子),同一链被多个父链各 jump 一次。
type ChainMount struct {
	Parent   string `json:"parent"`   // 父链 MYFW-INPUT/FORWARD/OUTPUT/PREROUTING/POSTROUTING/MANGLE
	Priority int    `json:"priority"` // 父链中 jump 到本子链的顺序,值小排前
}

// CustomChain 用户自定义子链:子链 MYFW-<name> 被一个或多个父链 jump 进来。
// 规则通过 GroupID(组即落点)落到子链,用于规则按业务归类。
// Parent/Priority 为兼容字段(主挂载 mounts[0] 的镜像,供旧代码/旧数据回退);
// Mounts 为权威挂载列表(JSON),读取优先 Mounts,空则回退 Parent/Priority(存量零迁移)。
type CustomChain struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:64;not null" json:"name"` // 子链名(MYFW-<name>)
	Parent      string    `gorm:"size:32;not null" json:"parent"`           // 兼容字段:主挂载父链(Mounts 镜像)
	Table       string    `gorm:"size:16;not null" json:"table"`            // 表 filter/nat/mangle,与父链一致
	Priority    int       `gorm:"index;default:50" json:"priority"`         // 兼容字段:主挂载优先级(Mounts 镜像)
	Mounts      string    `gorm:"type:text" json:"mounts"`                  // JSON []ChainMount,权威;空则回退 Parent/Priority
	Description string    `gorm:"size:512" json:"description"`
	Enabled     bool      `gorm:"index" json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MountList 返回权威挂载列表:Mounts 非空解析之,空则回退单挂载 Parent/Priority(存量兼容)。
// 供 compiler 展开 CustomChainDef(同名多 parent)与前端展示。
func (c *CustomChain) MountList() []ChainMount {
	if c.Mounts != "" {
		var ms []ChainMount
		if err := json.Unmarshal([]byte(c.Mounts), &ms); err == nil && len(ms) > 0 {
			return ms
		}
	}
	return []ChainMount{{Parent: c.Parent, Priority: c.Priority}}
}
