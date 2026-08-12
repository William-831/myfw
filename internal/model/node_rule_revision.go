package model

import "time"

// NodeRuleRevision 节点规则库版本档案(计划三:长期快照 + 任意时间点回滚)。
// 每次 Apply 成功后归档该节点的期望态规则集(编译产物 RuleSet,protojson 文本),
// 管理员可列历史版本并"一键回退整个节点规则库"到任意版本。
// 与 Snapshot(单次任务临时备份,Confirm/Rollback 后即失效)不同,这是长期档案,
// 按保留策略(最近 N 份)自动清理。Source: apply(变更归档)/manual(手动)/rollback(回滚前归档)。
type NodeRuleRevision struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	NodeID    string    `gorm:"size:64;index" json:"node_id"`
	RevNo     int64     `gorm:"index" json:"rev_no"` // 节点内单调递增版本号
	Source    string    `gorm:"size:16" json:"source"`
	TaskID    string    `gorm:"size:64" json:"task_id"` // 触发归档的任务,手动/回滚归档可为空
	Note      string    `gorm:"size:255" json:"note"`
	Payload   string    `gorm:"type:text" json:"payload"` // protojson 序列化的期望态 RuleSet
	Hash      string    `gorm:"size:128" json:"hash"`     // payload 的 SHA-256,便于比对重复变更
	CreatedAt time.Time `json:"created_at"`
}
