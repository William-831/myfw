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
)

// Task is a unit of firewall change dispatched to a single node.
type Task struct {
	ID           string     `gorm:"primaryKey;size:64" json:"id"`
	NodeID       string     `gorm:"size:64;index" json:"node_id"`
	PolicyID     uint       `gorm:"index" json:"policy_id"`
	PolicyName   string     `gorm:"size:255" json:"policy_name"` // 策略名快照,审批展示用(避免 policy 改/删后丢失)
	Status       TaskStatus `gorm:"size:24;index" json:"status"`
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
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
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

// AuditLog is the append-only record of every meaningful action (design.md § 11 / § 13.3.5).
type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Actor     string    `gorm:"size:128;index" json:"actor"`
	Action    string    `gorm:"size:64;index" json:"action"`
	NodeID    string    `gorm:"size:64;index" json:"node_id"`
	TaskID    string    `gorm:"size:64;index" json:"task_id"`
	Detail    string    `gorm:"type:text" json:"detail"`
	CreatedAt time.Time `gorm:"index" json:"created_at"`
}
