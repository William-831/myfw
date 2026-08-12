package model

import "time"

// RuleHitStat 节点规则命中统计(按 node+instance 唯一)。
// Agent 周期采集 iptables 计数器 + comment 反解实例 ID 后上报,Controller upsert。
// 死规则判定:实例 enabled=true + packets=0 + created_at 超阈值 -> dead。
type RuleHitStat struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	NodeID     string    `gorm:"index:idx_node_inst,unique;size:64" json:"node_id"`
	InstanceID uint      `gorm:"index:idx_node_inst,unique" json:"instance_id"`
	Packets    int64     `json:"packets"`
	Bytes      int64     `json:"bytes"`
	LastSeen   time.Time `gorm:"index" json:"last_seen"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
