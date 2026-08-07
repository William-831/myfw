package model

import "time"

// Policy is an abstract, cloud-security-group-style access rule authored by an
// admin (design.md § 6). It is compiled into CompiledRules before dispatch.
type Policy struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Name             string    `gorm:"size:255" json:"name"`
	Direction        string    `gorm:"size:16" json:"direction"`        // 废弃:两级模型下从组继承,保留字段不用
	GroupID          uint      `gorm:"index" json:"group_id"`           // 所属策略组(CustomChain.ID),条目继承组的方向/子链
	Source           string    `gorm:"size:128" json:"source"`          // IP/CIDR, empty = any
	Destination      string    `gorm:"size:128" json:"destination"`     // IP/CIDR, empty = any
	Protocol         string    `gorm:"size:16" json:"protocol"`         // TCP/UDP/ICMP/ANY
	PortRange        string    `gorm:"size:64" json:"port_range"`
	Action           string    `gorm:"size:16" json:"action"`
	Mark             uint32    `json:"mark"`
	NatTo            string    `gorm:"size:128" json:"nat_to"`
	SourceGroup      string    `gorm:"size:64" json:"source_group"`      // 引用 AddressGroup.name,编译为 set 匹配
	DestinationGroup string    `gorm:"size:64" json:"destination_group"` // 引用 AddressGroup.name
	MatchMark        uint32    `json:"match_mark"`                 // 匹配条件:已打标(与 Action=MARK 打标正交)
	Group            string    `gorm:"size:64" json:"group"`       // 逻辑分组(展示与编排)
	Chain            string    `gorm:"size:64" json:"chain"`             // 指定子链(MYFW-<name>),空则按 action/direction 落父链
	Priority         int       `gorm:"index" json:"priority"`
	Description      string    `gorm:"size:512" json:"description"`
	Targets          string    `gorm:"type:text" json:"targets"` // JSON-encoded []node_id or label selector
	Enabled          bool      `gorm:"index" json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PolicyVersion records an immutable snapshot of a policy's fields at the time
// a change was made, for diffing and rollback (design.md § 6 / § 11).
type PolicyVersion struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	PolicyID  uint      `gorm:"index" json:"policy_id"`
	Version   int64     `gorm:"index" json:"version"`
	Snapshot  string    `gorm:"type:text" json:"snapshot"` // JSON of the Policy at this version
	Author    string    `gorm:"size:128" json:"author"`
	Status    string    `gorm:"size:16;index" json:"status"` // pending/approved/rejected
	CreatedAt time.Time `json:"created_at"`
}

// Rule is a compiled, driver-agnostic rule materialized for a specific node
// and policy version (mirror of proto CompiledRule, persisted for audit/diff).
type Rule struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	NodeID      string    `gorm:"size:64;index" json:"node_id"`
	PolicyID    uint      `gorm:"index" json:"policy_id"`
	Version     int64     `gorm:"index" json:"version"`
	Direction   string    `gorm:"size:16" json:"direction"`
	Source      string    `gorm:"size:128" json:"source"`
	Destination string    `gorm:"size:128" json:"destination"`
	Protocol    string    `gorm:"size:16" json:"protocol"`
	PortRange   string    `gorm:"size:64" json:"port_range"`
	Action      string    `gorm:"size:16" json:"action"`
	Mark        uint32    `json:"mark"`
	NatTo       string    `gorm:"size:128" json:"nat_to"`
	Priority    int       `json:"priority"`
	CreatedAt   time.Time `json:"created_at"`
}
