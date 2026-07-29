package model

import "time"

// AddressGroup 地址组:白名单/黑名单的 IP/CIDR 集合,编译期绑定到节点上的
// ipset / nft set。一个组对应节点上的一个 MYFW-<name> 集合,Policy 通过
// SourceGroup / DestinationGroup 引用其名称。See docs/design.md § 6.
type AddressGroup struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `gorm:"uniqueIndex;size:64;not null" json:"name"` // whitelist / blacklist / 自定义,节点集合名 MYFW-<name>
	Kind        string    `gorm:"size:16;not null" json:"kind"`             // whitelist | blacklist | custom
	Members     string    `gorm:"type:text" json:"members"`                 // JSON: ["10.0.0.0/8","192.168.1.0/24"]
	Description string    `gorm:"size:512" json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
