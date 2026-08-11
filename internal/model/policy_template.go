package model

import "time"

// PolicyTemplate 是可复用的规则骨架:归属策略组(CustomChain),定义动作/协议/端口等
// 默认参数,不绑定任何节点。节点策略实例从模板实例化并独立保存参数快照。
// SpecVersion 是规则字段的单调递增版本号,实例据此判 drift——比 UpdatedAt 更精确:
// 改名称/描述等非规则字段不递增,不会误触发节点实例 drift(漏洞 A 修复)。
type PolicyTemplate struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Name             string    `gorm:"size:255" json:"name"`
	GroupID          uint      `gorm:"index" json:"group_id"` // 继承的落点链(兼容:落点默认随组),调度语义
	ChainID          uint      `gorm:"index" json:"chain_id"` // 独立落点链(与组解耦):>0 时规则落该链,0=继承 GroupID 组链
	Direction        string    `gorm:"size:16" json:"direction"` // MARK 白名单流量方向:FORWARD(容器转发)/INPUT(主机入站),仅 MARK+白名单用
	Source           string    `gorm:"size:128" json:"source"`
	Destination      string    `gorm:"size:128" json:"destination"`
	Protocol         string    `gorm:"size:16" json:"protocol"`
	PortRange        string    `gorm:"size:64" json:"port_range"`
	Action           string    `gorm:"size:16" json:"action"`
	Mark             uint32    `json:"mark"`
	NatTo            string    `gorm:"size:128" json:"nat_to"`
	SourceGroup      string    `gorm:"size:64" json:"source_group"`
	DestinationGroup string    `gorm:"size:64" json:"destination_group"`
	MatchMark        uint32    `json:"match_mark"` // 仅供 MARK 白名单编译内部使用(匹配已打标流量),非用户输入,前端已移除入口
	Priority         int       `gorm:"index" json:"priority"`
	Description      string    `gorm:"size:512" json:"description"`
	Enabled          bool      `gorm:"index" json:"enabled"`
	SpecVersion      int64     `json:"spec_version"`
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
	ChainID          uint      `gorm:"index" json:"chain_id"` // 独立落点链(与组解耦):>0 时规则落该链,0=继承 GroupID 组链
	Direction        string    `gorm:"size:16" json:"direction"` // MARK 白名单流量方向:FORWARD(容器转发)/INPUT(主机入站),仅 MARK+白名单用
	Source           string    `gorm:"size:128" json:"source"`
	Destination      string    `gorm:"size:128" json:"destination"`
	Protocol         string    `gorm:"size:16" json:"protocol"`
	PortRange        string    `gorm:"size:64" json:"port_range"`
	Action           string    `gorm:"size:16" json:"action"`
	Mark             uint32    `json:"mark"`
	NatTo            string    `gorm:"size:128" json:"nat_to"`
	SourceGroup      string    `gorm:"size:64" json:"source_group"`
	DestinationGroup string    `gorm:"size:64" json:"destination_group"`
	MatchMark        uint32    `json:"match_mark"` // 仅供 MARK 白名单编译内部使用(匹配已打标流量),非用户输入,前端已移除入口
	Priority         int       `gorm:"index" json:"priority"`
	Description      string    `gorm:"size:512" json:"description"`
	Enabled          bool      `gorm:"index" json:"enabled"`
	Applied          bool      `gorm:"index;default:false" json:"applied"`
	// PendingDelete 标记实例待删除:用户点"移除"且节点上有规则(applied=true)时置 true,
	// 走 dispatch 移除下发并进入保护期。Confirm 时物理删除,Rollback 时恢复。
	PendingDelete bool `gorm:"index;default:false" json:"pending_delete"`
	// PendingDeleteTaskID 关联本次移除操作的 task_id,Confirm/Rollback 据此精确清理或恢复
	// 对应实例,避免同节点多个保护期 task 互相误伤。
	PendingDeleteTaskID string `gorm:"size:64;index" json:"pending_delete_task_id"`
	// SyncedSpecVersion 上次同步/实例化时模板的 SpecVersion。drift 据此判断模板
	// 规则字段是否在实例之后更新过--实例自身编辑不视为 drift(用户主动偏离模板)。
	// 相比旧的 SyncedTemplateUpdatedAt 时间戳判据,SpecVersion 不受 DB 时间精度影响,
	// 且改模板名称/描述不会误报 drift(漏洞 A 修复)。
	SyncedSpecVersion int64 `gorm:"index" json:"synced_spec_version"`
	// SyncedTemplateUpdatedAt 保留兼容旧数据的时间戳判据;新数据统一用 SyncedSpecVersion。
	SyncedTemplateUpdatedAt time.Time `gorm:"column:synced_template_at;index" json:"synced_template_at"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}
