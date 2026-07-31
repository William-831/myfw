// Package model holds the GORM entities persisted by the Controller.
//
// The same structs run against SQLite (dev) and OceanBase/MySQL (prod), so
// avoid backend-specific column types and rely on GORM's portable tags.
// See docs/design.md § 2 and docs/development-plan.md § M1.
package model

import "time"

// NodeStatus is the lifecycle state of a managed node (design.md § 13.3).
type NodeStatus string

const (
	NodeStatusPending  NodeStatus = "PENDING"  // registered, awaiting admin approval
	NodeStatusActive   NodeStatus = "ACTIVE"   // approved, may receive rule dispatch
	NodeStatusAbnormal NodeStatus = "ABNORMAL" // 在线但防火墙后端不可用，需登录节点排查
	NodeStatusOffline  NodeStatus = "OFFLINE"  // being decommissioned
	NodeStatusArchived NodeStatus = "ARCHIVED" // retired, kept for audit
)

// Node is a managed Linux host running an Agent.
type Node struct {
	ID        string     `gorm:"primaryKey;size:64" json:"id"` // final node_id
	Status    NodeStatus `gorm:"size:16;index" json:"status"`
	Hostname  string     `gorm:"size:255" json:"hostname"`
	IP        string     `gorm:"size:64" json:"ip"` // Agent 上报的 IP 地址
	MachineID string     `gorm:"size:128;index" json:"machine_id"`
	Arch      string     `gorm:"size:32" json:"arch"`
	Labels    string     `gorm:"type:text" json:"labels"` // JSON-encoded []string
	LastSeen  *time.Time `json:"last_seen"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	Capability *NodeCapability `gorm:"foreignKey:NodeID" json:"capability,omitempty"`

	// DriftCount 该节点 drift 实例数(实例参数 vs 模板当前参数),非持久化,
	// 由节点列表接口聚合返回,供节点列表角标提示模板更新未同步。
	DriftCount int `gorm:"-" json:"drift_count"`
}

// NodeCapability is the latest probe result reported by a node's Agent.
type NodeCapability struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	NodeID           string    `gorm:"size:64;uniqueIndex" json:"node_id"`
	Distro           string    `gorm:"size:128" json:"distro"`
	KernelVersion    string    `gorm:"size:128" json:"kernel_version"`
	IptablesVersion  string    `gorm:"size:64" json:"iptables_version"`
	SelectedBackend  string    `gorm:"size:32" json:"selected_backend"`
	BackendAvailable *bool     `gorm:"index" json:"backend_available"` // nil=未上报；true/false=Agent 探测结果
	BackendReason    string    `gorm:"size:255" json:"backend_reason"` // 后端不可用原因，引导管理员排查
	NftSupported     bool      `json:"nft_supported"`
	DockerPresent    bool      `json:"docker_present"`
	K8sPresent       bool      `json:"k8s_present"`
	Raw              string    `gorm:"type:text" json:"raw"` // JSON snapshot of full capability
	UpdatedAt        time.Time `json:"updated_at"`
}

// Certificate binds an issued client certificate fingerprint to a node
// (design.md § 13.3.3). Only one active cert per node at a time.
type Certificate struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	NodeID      string     `gorm:"size:64;index" json:"node_id"`
	Fingerprint string     `gorm:"size:128;uniqueIndex" json:"fingerprint"` // SHA-256 of DER
	SerialHex   string     `gorm:"size:64" json:"serial_hex"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	Revoked     bool       `gorm:"index" json:"revoked"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// BootstrapToken is a one-time, short-lived token used for first registration
// (design.md § 13.2).
type BootstrapToken struct {
	ID        uint       `gorm:"primaryKey" json:"id"`
	Token     string     `gorm:"size:128;uniqueIndex" json:"token"`
	Note      string     `gorm:"size:255" json:"note"`
	ExpiresAt time.Time  `gorm:"index" json:"expires_at"`
	UsedAt    *time.Time `json:"used_at"`
	CreatedAt time.Time  `json:"created_at"`
}
