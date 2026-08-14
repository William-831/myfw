package model

import "time"

// TaskStatus is the change-task state machine (design.md § 11, development-plan § M7).
type TaskStatus string

const (
	TaskDraft           TaskStatus = "draft"
	TaskPendingApproval TaskStatus = "pending_approval"
	TaskApproved        TaskStatus = "approved"
	TaskDispatching     TaskStatus = "dispatching"
	TaskApplying        TaskStatus = "applying"
	TaskConfirmWait     TaskStatus = "confirm_wait"
	TaskConfirmed       TaskStatus = "confirmed"
	TaskRolledBack      TaskStatus = "rolled_back"
	TaskFailed          TaskStatus = "failed"
	// TaskSuperseded 保护期动作合并接管:节点在新任务下发前存在旧保护期任务时,
	// 旧任务被置为 superseded 终态(不再回滚,Agent 快照经 Confirm 语义释放)。
	// 由 Coordinator.SupersedeInFlight 设置。
	TaskSuperseded TaskStatus = "superseded"
)

// Task is a unit of firewall change dispatched to a single node.
type Task struct {
	ID           string     `gorm:"primaryKey;size:64" json:"id"`
	NodeID       string     `gorm:"size:64;index;index:idx_task_node_status,priority:1" json:"node_id"` // 复合索引(node_id,status)见 Status 注释
	PolicyID     uint       `gorm:"index" json:"policy_id"`
	PolicyName   string     `gorm:"size:255" json:"policy_name"` // 策略名快照,审批展示用(避免 policy 改/删后丢失)
	ChangeType   string     `gorm:"size:16" json:"change_type"`  // 变更类型:dispatch(下发)/disable(禁用)/mixed(混合),节点级 dispatch 填充,前端据此标注
	// 复合索引 idx_task_node_status(node_id, status):保护期接管(SupersedeInFlight)、
	// 前端 4 状态刷新、HasInFlight 去重均按"节点+状态"过滤,单列索引不足(B1 优化)。
	Status       TaskStatus `gorm:"size:24;index;index:idx_task_node_status,priority:2" json:"status"`
	Version      int64      `json:"version"`
	DiffBefore   string     `gorm:"type:text" json:"diff_before"`
	DiffAfter    string     `gorm:"type:text" json:"diff_after"`
	ExpectedHash string     `gorm:"size:128" json:"expected_hash"`
	ResultHash   string     `gorm:"size:128" json:"result_hash"`
	Message      string     `gorm:"size:512" json:"message"`
	// ConfirmDeadline is when the confirm-wait timer expires and the Controller
	// should trigger an auto-rollback (design.md § 11). Set at Apply time,
	// used by the coordinator on both live runs and startup recovery.
	ConfirmDeadline *time.Time `json:"confirm_deadline"`
	Reviewer        string     `gorm:"size:128" json:"reviewer,omitempty"`
	// AutoConfirm 系统自愈任务标记(drift 恢复):apply 成功后直接 confirmed,
	// 不进 confirm_wait 保护期。修复自愈死循环——自愈是系统行为,无人工确认,
	// 若走保护期必然超时回滚,回滚恢复快照≠expected 又触发再漂移。
	AutoConfirm bool `gorm:"default:false" json:"auto_confirm,omitempty"`
	// RuleSetSnapshot 回滚任务携带的历史规则集快照(protojson RuleSet)。
	// 非空时 dispatch 直接用它下发、跳过重新编译——支撑规则库版本回滚(计划三)。
	// 普通任务为空。
	RuleSetSnapshot string    `gorm:"type:text" json:"rule_set_snapshot,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Approval records the review decision on a task before it may be applied.
type Approval struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	TaskID    string    `gorm:"size:64;index" json:"task_id"`
	Approved  bool      `json:"approved"`
	Reviewer  string    `gorm:"size:128" json:"reviewer"`
	Comment   string    `gorm:"size:512" json:"comment"`
	CreatedAt time.Time `json:"created_at"`
}

// Snapshot is a node's pre-Apply firewall backup, used for rollback
// (design.md § 11). Scope is the MYFW namespace only.
type Snapshot struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	NodeID    string    `gorm:"size:64;index" json:"node_id"`
	TaskID    string    `gorm:"size:64;index" json:"task_id"`
	Backend   string    `gorm:"size:32" json:"backend"`
	Payload   string    `gorm:"type:text" json:"payload"` // iptables-save / nft dump of MYFW scope
	Hash      string    `gorm:"size:128" json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

// AuditLog 审计流水,append-only。每条记录一个动作(状态流转/操作)。
// Scene/Result/ProtectionWindow 为结构化索引列,便于聚合统计保护期变更仪表盘(design.md § 10)。
type AuditLog struct {
	ID               uint      `gorm:"primaryKey" json:"id"`
	Actor            string    `gorm:"size:128;index" json:"actor"`
	Action           string    `gorm:"size:64;index" json:"action"`
	Scene            string    `gorm:"size:24;index" json:"scene"`  // normal/expert_bypass/auto_rollback/recovery
	Result           string    `gorm:"size:16;index" json:"result"` // success/failed/rolled_back/pending
	NodeID           string    `gorm:"size:64;index;index:idx_audit_node_created,priority:1" json:"node_id"`
	TaskID           string    `gorm:"size:64;index" json:"task_id"`
	Detail           string    `gorm:"type:text" json:"detail"`
	ProtectionWindow int       `json:"protection_window,omitempty"` // 保护期剩余秒数(仅 applying_ok 填)
	// 复合索引 idx_audit_node_created(node_id, created_at):审计按节点过滤+时间倒序分页,避免 filesort(B1 优化)。
	CreatedAt        time.Time `gorm:"index;index:idx_audit_node_created,priority:2" json:"created_at"`
}

// 审计场景与结果常量
const (
	AuditSceneNormal       = "normal"        // 常规保护期变更
	AuditSceneExpertBypass = "expert_bypass" // 专家终端绕过保护期
	AuditSceneAutoRollback = "auto_rollback" // 超时自动回滚
	AuditSceneRecovery     = "recovery"      // 启动恢复
	AuditSceneSelfHeal     = "self_heal"     // 系统自愈(drift 恢复),与人工操作区分
	AuditSceneRevisionRollback = "revision_rollback" // 规则库版本回滚(计划三):下发历史规则集,临时排障手段

	AuditResultSuccess    = "success"
	AuditResultFailed     = "failed"
	AuditResultRolledBack = "rolled_back"
	AuditResultPending    = "pending"
)
