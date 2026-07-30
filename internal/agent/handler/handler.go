// Package handler bridges Controller-to-Agent messages to a Firewall Driver.
// It is the concrete conn.Handler used at runtime.
package handler

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/agent/driver"
)

// Driver is the subset of driver.Driver that Handler needs. Kept small so it
// can be faked by tests without pulling in every method.
type Driver interface {
	Apply(ctx context.Context, ruleSet *myfwv1.RuleSet) (string, error)
	Snapshot(ctx context.Context) (payload string, hash string, err error)
	Restore(ctx context.Context, payload string) error
}

// HashNotifier is called when an Apply succeeds, so the Watchdog can update
// its expected hash baseline.
type HashNotifier interface {
	SetExpectedHash(hash string)
}

// Handler dispatches ApplyTask/ConfirmTask/RollbackTask to a Driver. It keeps
// the pre-Apply snapshot in memory so a subsequent Rollback can restore it.
type Handler struct {
	D   Driver
	Log *slog.Logger

	// HashNotifier receives the hash after a successful Apply.
	HashNotifier HashNotifier

	// RulesCollector, if set, supplies the node's current iptables rules when
	// the Controller requests a real-time sync. Injected by cmd/agent.
	RulesCollector func() (map[string]map[string][]string, error)

	// RuleExecutor 执行单条 iptables 命令（增删改插），由 cmd/agent 注入。
	RuleExecutor func(ctx context.Context, args []string) (string, error)

	// ExecExecutor 专家模式执行任意 iptables 族命令（白名单校验后调用），由 cmd/agent 注入。
	ExecExecutor func(ctx context.Context, name string, args []string) (string, error)

	// last snapshot taken before Apply, keyed by TaskId — read when Rollback
	// arrives, cleared on Confirm.
	last map[string]string
}

// New builds a Handler around drv. If drv is nil, Apply tasks are rejected
// with a clear message (useful during dev on macOS where no real driver is
// available).
func New(drv Driver, log *slog.Logger) *Handler {
	return &Handler{D: drv, Log: log, last: map[string]string{}}
}

// SetHashNotifier registers a notifier to receive successful Apply hashes.
func (h *Handler) SetHashNotifier(n HashNotifier) {
	h.HashNotifier = n
}

// OnApply snapshots the current namespace, then applies the new RuleSet.
// The snapshot is retained so a later RollbackTask can restore it.
func (h *Handler) OnApply(ctx context.Context, task *myfwv1.ApplyTask) *myfwv1.TaskResult {
	res := &myfwv1.TaskResult{TaskId: task.TaskId, TsUnix: time.Now().Unix()}

	if h.D == nil {
		res.Message = "no firewall driver on this host"
		return res
	}
	if task.RuleSet == nil {
		res.Message = "empty RuleSet"
		return res
	}

	snap, _, err := h.D.Snapshot(ctx)
	if err != nil {
		res.Message = "snapshot failed: " + err.Error()
		return res
	}
	h.last[task.TaskId] = snap

	hash, err := h.D.Apply(ctx, task.RuleSet)
	if err != nil {
		// Best-effort self-rollback: try to restore the snapshot we just took
		// so a mid-Apply failure doesn't leave the host in a bad state. If
		// this also fails we surface both errors.
		if rbErr := h.D.Restore(ctx, snap); rbErr != nil {
			h.Log.Error("apply failed AND self-rollback failed",
				"apply_err", err, "rollback_err", rbErr, "task_id", task.TaskId)
			res.Message = "apply failed: " + err.Error() + " (self-rollback also failed: " + rbErr.Error() + ")"
			return res
		}
		res.Message = "apply failed: " + err.Error() + " (self-rolled back)"
		return res
	}

	res.Ok = true
	res.ResultHash = hash

	// Notify Watchdog of the new expected hash.
	if h.HashNotifier != nil {
		h.HashNotifier.SetExpectedHash(hash)
	}

	return res
}

// OnConfirm discards the snapshot we kept for this task — the change is now
// considered stable.
func (h *Handler) OnConfirm(ctx context.Context, task *myfwv1.ConfirmTask) {
	delete(h.last, task.TaskId)
	h.Log.Info("apply confirmed", "task_id", task.TaskId)
}

// OnRollback restores the pre-Apply snapshot for the given task.
func (h *Handler) OnRollback(ctx context.Context, task *myfwv1.RollbackTask) {
	snap, ok := h.last[task.TaskId]
	if !ok {
		h.Log.Warn("rollback requested but no snapshot on hand", "task_id", task.TaskId)
		return
	}
	if err := h.D.Restore(ctx, snap); err != nil {
		h.Log.Error("rollback failed", "task_id", task.TaskId, "err", err)
		return
	}
	delete(h.last, task.TaskId)
	h.Log.Info("rolled back", "task_id", task.TaskId)
}

// OnSyncRules collects the node's current iptables rules in response to a
// SyncRulesRequest. Returns nil if no collector is wired.
func (h *Handler) OnSyncRules(ctx context.Context) *myfwv1.IptablesRules {
	if h.RulesCollector == nil {
		return nil
	}
	rules, err := h.RulesCollector()
	if err != nil {
		h.Log.Warn("collect iptables rules failed", "err", err)
		return nil
	}
	chains := make([]*myfwv1.IptablesChain, 0)
	for table, tableChains := range rules {
		for chain, chainRules := range tableChains {
			chains = append(chains, &myfwv1.IptablesChain{
				Table: table,
				Chain: chain,
				Rules: chainRules,
			})
		}
	}
	return &myfwv1.IptablesRules{
		TsUnix: time.Now().Unix(),
		Chains: chains,
	}
}

// OnRuleOperation 执行单条规则增删改插，构造 iptables 命令并执行。
// 双模式：专家模式直接用 rule_line；结构化模式由 action/protocol/源/目的/端口翻译。
func (h *Handler) OnRuleOperation(ctx context.Context, op *myfwv1.RuleOperation) *myfwv1.TaskResult {
	res := &myfwv1.TaskResult{TaskId: op.TaskId, TsUnix: time.Now().Unix()}
	if h.RuleExecutor == nil {
		res.Message = "no rule executor configured"
		return res
	}
	args, err := buildIptablesArgs(op)
	if err != nil {
		res.Message = "build command: " + err.Error()
		return res
	}
	out, err := h.RuleExecutor(ctx, args)
	if err != nil {
		res.Message = "exec failed: " + err.Error() + " | " + strings.TrimSpace(out)
		return res
	}
	res.Ok = true
	res.Message = "iptables " + strings.Join(args, " ")
	return res
}

// iptablesExecAllowed 专家模式允许执行的命令白名单（iptables 族）。
// 拒绝任意 shell 命令，防止专家模式退化为 webshell。
var iptablesExecAllowed = map[string]bool{
	"iptables":         true,
	"ip6tables":        true,
	"iptables-save":    true,
	"iptables-restore": true,
	"nft":              true,
}

// OnExec 专家模式：执行裸 iptables 命令。校验首 token 必须属于 iptables 族
// 白名单，执行后回 TaskResult（message=stdout/stderr，ok=exit 0）。
// 注意：此通道绕过 MYFW 命名空间/快照/保护期，调用方须强审计留痕。
func (h *Handler) OnExec(ctx context.Context, cmd *myfwv1.ExecCommand) *myfwv1.TaskResult {
	res := &myfwv1.TaskResult{TaskId: cmd.TaskId, TsUnix: time.Now().Unix()}
	if h.ExecExecutor == nil {
		res.Message = "no exec executor configured"
		return res
	}
	fields := strings.Fields(cmd.Command)
	if len(fields) == 0 {
		res.Message = "empty command"
		return res
	}
	base := filepath.Base(fields[0])
	if !iptablesExecAllowed[base] {
		res.Message = "command not allowed: " + base + " (仅允许 iptables 族: iptables/ip6tables/iptables-save/iptables-restore/nft)"
		return res
	}
	out, err := h.ExecExecutor(ctx, fields[0], fields[1:])
	out = strings.TrimSpace(out)
	if err != nil {
		res.Message = "exec failed: " + err.Error() + " | " + out
		return res
	}
	res.Ok = true
	res.Message = out
	return res
}

// buildIptablesArgs 把 RuleOperation 翻译成 iptables 命令参数。
func buildIptablesArgs(op *myfwv1.RuleOperation) ([]string, error) {
	table := op.Table
	if table == "" {
		table = "filter"
	}
	chain := strings.TrimSpace(op.Chain)
	if chain == "" {
		return nil, errors.New("chain required")
	}
	// 收敛 MYFW:节点级直操作只能改 MYFW-* 自定义链,拒绝直接操作内置链
	// (INPUT/FORWARD/OUTPUT/PREROUTING/POSTROUTING),内置链由平台 jump 接管。
	if !strings.HasPrefix(chain, "MYFW-") {
		return nil, errors.New("chain must be MYFW-* (内置链由平台 jump 接管,不直接操作)")
	}
	var flag string
	switch op.Op {
	case myfwv1.RuleOpType_RULE_OP_ADD:
		flag = "-A"
	case myfwv1.RuleOpType_RULE_OP_INSERT:
		flag = "-I"
	case myfwv1.RuleOpType_RULE_OP_DELETE:
		flag = "-D"
	case myfwv1.RuleOpType_RULE_OP_REPLACE:
		flag = "-R"
	default:
		return nil, errors.New("invalid op")
	}
	args := []string{"-t", table, flag, chain}
	if (op.Op == myfwv1.RuleOpType_RULE_OP_INSERT || op.Op == myfwv1.RuleOpType_RULE_OP_REPLACE) && op.Position > 0 {
		args = append(args, strconv.Itoa(int(op.Position)))
	}
	ruleLine := strings.TrimSpace(op.RuleLine)
	if ruleLine == "" {
		rl, err := buildRuleLineFromStructured(op)
		if err != nil {
			return nil, err
		}
		ruleLine = rl
	}
	args = append(args, strings.Fields(ruleLine)...)
	return args, nil
}

// buildRuleLineFromStructured 结构化字段翻译为 iptables 规则体。
func buildRuleLineFromStructured(op *myfwv1.RuleOperation) (string, error) {
	if op.Action == "" {
		return "", errors.New("action required for structured mode")
	}
	var parts []string
	if op.Protocol != "" && op.Protocol != "any" {
		parts = append(parts, "-p", op.Protocol)
	}
	if op.Source != "" {
		parts = append(parts, "-s", op.Source)
	}
	if op.Destination != "" {
		parts = append(parts, "-d", op.Destination)
	}
	if op.Port != "" && op.Protocol != "icmp" {
		parts = append(parts, "--dport", op.Port)
	}
	parts = append(parts, "-j", strings.ToUpper(op.Action))
	return strings.Join(parts, " "), nil
}

// static check: Handler satisfies conn.Handler (defined in sibling package).
// We can't import conn here without a cycle, so this remains an implicit
// contract enforced by the compilation of cmd/agent/main.go.
var _ = (*driver.Driver)(nil) // keep the driver package referenced
