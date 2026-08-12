// Package revision 维护节点规则库版本档案(计划三:长期快照 + 任意时间点回滚)。
// 每次 Apply 成功后归档该节点期望态规则集;管理员可列历史版本,并回滚到任意版本
// (用历史 RuleSet 直接下发,走正常保护期,Agent 快照机制天然支持"撤销回滚")。
package revision

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/compiler"
	"iptables-tool/internal/model"
)

// defaultKeep 默认保留最近 N 份版本,超出部分在归档时清理(保留策略)。
const defaultKeep = 30

// Service 提供规则库版本档案的归档/列表/读取。回滚下发由上层(路由)编排:
// 归档当前版本 -> Load 历史版本 -> Coordinator.SubmitRuleSet,本包不依赖 task 包。
type Service struct {
	DB   *gorm.DB
	Comp *compiler.Compiler
	Log  *slog.Logger
}

func New(db *gorm.DB, comp *compiler.Compiler, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{DB: db, Comp: comp, Log: log}
}

// ArchiveApply 在 Apply 成功后归档节点期望态规则集(source=apply)。
// 从 DB 重新编译期望态,不依赖 Agent 在线,保证回滚用的是"该时刻应有的规则集"。
func (s *Service) ArchiveApply(ctx context.Context, nodeID, taskID string) error {
	return s.Archive(ctx, nodeID, "apply", taskID, "")
}

// Archive 归档节点当前期望态规则集,source 标识触发来源(apply/manual/rollback)。
// 事务内:写入新版本(rev_no 递增)+ 按保留策略清理最旧版本。
func (s *Service) Archive(ctx context.Context, nodeID, source, taskID, note string) error {
	rules, sets, chains, err := s.Comp.CompileForNode(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("revision: compile node %s: %w", nodeID, err)
	}
	rs := &myfwv1.RuleSet{NodeId: nodeID, Rules: rules, Sets: sets, CustomChains: chains}
	payload, err := protojson.Marshal(rs)
	if err != nil {
		return fmt.Errorf("revision: marshal ruleset: %w", err)
	}
	sum := sha256.Sum256(payload)
	hash := hex.EncodeToString(sum[:])

	return s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var max int64
		if err := tx.Model(&model.NodeRuleRevision{}).
			Where("node_id = ?", nodeID).
			Select("COALESCE(MAX(rev_no),0)").Scan(&max).Error; err != nil {
			return err
		}
		rev := model.NodeRuleRevision{
			NodeID: nodeID, RevNo: max + 1, Source: source,
			TaskID: taskID, Note: note, Payload: string(payload),
			Hash: hash, CreatedAt: time.Now(),
		}
		if err := tx.Create(&rev).Error; err != nil {
			return err
		}
		return s.prune(tx, nodeID)
	})
}

// List 返回节点历史版本(新 -> 旧)。
func (s *Service) List(ctx context.Context, nodeID string) ([]model.NodeRuleRevision, error) {
	var revs []model.NodeRuleRevision
	if err := s.DB.WithContext(ctx).Where("node_id = ?", nodeID).
		Order("rev_no DESC").Find(&revs).Error; err != nil {
		return nil, err
	}
	return revs, nil
}

// Load 读取指定版本并反序列化为可下发的 RuleSet(补齐 NodeId)。
func (s *Service) Load(ctx context.Context, nodeID string, revNo int64) (*myfwv1.RuleSet, error) {
	var rev model.NodeRuleRevision
	if err := s.DB.WithContext(ctx).Where("node_id = ? AND rev_no = ?", nodeID, revNo).
		First(&rev).Error; err != nil {
		return nil, err
	}
	var rs myfwv1.RuleSet
	if err := protojson.Unmarshal([]byte(rev.Payload), &rs); err != nil {
		return nil, fmt.Errorf("revision: unmarshal rev %d: %w", revNo, err)
	}
	rs.NodeId = nodeID
	return &rs, nil
}

// prune 保留最近 defaultKeep 份(rev_no 最大的 N 条),删除更旧的。
func (s *Service) prune(tx *gorm.DB, nodeID string) error {
	var keep []uint
	if err := tx.Model(&model.NodeRuleRevision{}).
		Where("node_id = ?", nodeID).Order("rev_no DESC").
		Limit(defaultKeep).Pluck("id", &keep).Error; err != nil {
		return err
	}
	if len(keep) == 0 {
		return nil
	}
	return tx.Where("node_id = ? AND id NOT IN ?", nodeID, keep).
		Delete(&model.NodeRuleRevision{}).Error
}
