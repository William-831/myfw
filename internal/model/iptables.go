package model

import "time"

// IptablesRule 存储节点的 iptables 规则
type IptablesRule struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	NodeID    string    `gorm:"index;size:64" json:"node_id"`
	TableType string    `gorm:"column:table_type;size:32" json:"table_type"` // filter, nat, mangle, raw
	Chain     string    `gorm:"size:32" json:"chain"`                       // INPUT, OUTPUT, FORWARD, etc.
	RuleLine  string    `gorm:"type:text" json:"rule_line"`                 // iptables -S 输出的规则行
	Priority  int       `json:"priority"`                                   // 规则顺序
	IsMYFW    bool      `json:"is_myfw"`                                    // 是否是 MYFW 命名空间的规则
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
