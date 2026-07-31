package model

import "time"

// PolicyTemplate 是可复用的规则骨架:归属策略组(CustomChain),定义动作/协议/端口等
// 默认参数,不绑定任何节点。节点策略实例从模板实例化并独立保存参数快照。
type PolicyTemplate struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Name             string    `gorm:"size:255" json:"name"`
	GroupID          uint      `gorm:"index" json:"group_id"` // 所属策略组,继承方向/子链/全局优先级
	Source           string    `gorm:"size:128" json:"source"`
	Destination      string    `gorm:"size:128" json:"destination"`
	Protocol         string    `gorm:"size:16" json:"protocol"`
	PortRange        string    `gorm:"size:64" json:"port_range"`
	Action           string    `gorm:"size:16" json:"action"`
	Mark             uint32    `json:"mark"`
	NatTo            string    `gorm:"size:128" json:"nat_to"`
	SourceGroup      string    `gorm:"size:64" json:"source_group"`
	DestinationGroup string    `gorm:"size:64" json:"destination_group"`
	MatchMark        uint32    `json:"match_mark"`
	MarkACLGroupID   uint      `gorm:"index" json:"mark_acl_group_id"`
	Priority         int       `gorm:"index" json:"priority"`
	Description      string    `gorm:"size:512" json:"description"`
	Enabled          bool      `gorm:"index" json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// NodePolicyInstance 是节点上的策略实例:创建时从模板全量复制参数,编译只读实例,
// 模板修改不影响已存在实例(独立参数快照)。TemplateID 用于 drift 检测与手动同步。
// Applied 标记是否已下发到节点:编辑/新增/启停/同步后置 false,dispatch 后置 true。
type NodePolicyInstance struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	TemplateID       uint      `gorm:"index" json:"template_id"`
	NodeID           string    `gorm:"size:64;index" json:"node_id"`
	Name             string    `gorm:"size:255" json:"name"`
	GroupID          uint      `gorm:"index" json:"group_id"`
	Source           string    `gorm:"size:128" json:"source"`
	Destination      string    `gorm:"size:128" json:"destination"`
	Protocol         string    `gorm:"size:16" json:"protocol"`
	PortRange        string    `gorm:"size:64" json:"port_range"`
	Action           string    `gorm:"size:16" json:"action"`
	Mark             uint32    `json:"mark"`
	NatTo            string    `gorm:"size:128" json:"nat_to"`
	SourceGroup      string    `gorm:"size:64" json:"source_group"`
	DestinationGroup string    `gorm:"size:64" json:"destination_group"`
	MatchMark        uint32    `json:"match_mark"`
	MarkACLGroupID   uint      `gorm:"index" json:"mark_acl_group_id"`
	Priority         int       `gorm:"index" json:"priority"`
	Description      string    `gorm:"size:512" json:"description"`
	Enabled          bool      `gorm:"index" json:"enabled"`
	Applied          bool      `gorm:"index;default:false" json:"applied"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}
