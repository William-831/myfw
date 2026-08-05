// Package audit is a thin persistence-layer wrapper around model.AuditLog.
// Every meaningful action in the Controller should call Write so we build the
// append-only history required by design.md § 10 / § 13.3.5.
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

type Sink struct {
	DB *gorm.DB
}

func New(db *gorm.DB) *Sink { return &Sink{DB: db} }

// Write persists an audit entry. CreatedAt is stamped here if unset.
func (s *Sink) Write(ctx context.Context, e model.AuditLog) error {
	if s == nil || s.DB == nil {
		return nil
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}
	return s.DB.WithContext(ctx).Create(&e).Error
}

// Query 分页查询审计流水,支持 action(模糊)/node_id/scene/result 过滤。
func (s *Sink) Query(ctx context.Context, action, nodeID, scene, result string, limit, offset int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64
	q := s.DB.WithContext(ctx).Model(&model.AuditLog{})
	if action != "" {
		q = q.Where("action LIKE ?", "%"+action+"%")
	}
	if nodeID != "" {
		q = q.Where("node_id = ?", nodeID)
	}
	if scene != "" {
		q = q.Where("scene = ?", scene)
	}
	if result != "" {
		q = q.Where("result = ?", result)
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}

// DashboardStats 保护期变更仪表盘统计(design.md § 10)。
type DashboardStats struct {
	Summary      map[string]int `json:"summary"`      // submit/confirmed/manual_rollback/auto_rollback/failed/expert_bypass/total/drift_count/self_heal
	Distribution map[string]int `json:"distribution"` // success/rolled_back/failed/pending
	Daily        []DailyStat    `json:"daily"`        // 按天聚合趋势,含 Drift 字段
	HealthRate   float64        `json:"health_rate"`  // 健康率 = confirmed / (confirmed + rolled_back + failed)
	RollbackCost float64        `json:"rollback_cost"` // 回滚消耗 = (auto_rollback + manual_rollback) / submit
}

// DailyStat 单日保护期变更趋势。
type DailyStat struct {
	Date     string `json:"date"`
	Submit   int    `json:"submit"`
	Confirm  int    `json:"confirm"`
	Rollback int    `json:"rollback"`
	Expert   int    `json:"expert"`
	Drift    int    `json:"drift"` // 漂移事件
}

// Dashboard 聚合近 days 天保护期变更统计:按 action 计数汇总指标 + 按天趋势。
// 专家终端(iptables.exec)单独计入 expert_bypass,不计入保护期变更终态分布。
func (s *Sink) Dashboard(ctx context.Context, days int) (*DashboardStats, error) {
	if s == nil || s.DB == nil {
		return &DashboardStats{Summary: map[string]int{}, Distribution: map[string]int{}}, nil
	}
	if days <= 0 {
		days = 7
	}
	since := time.Now().AddDate(0, 0, -days)
	stats := &DashboardStats{Summary: map[string]int{}, Distribution: map[string]int{}}

	// 按 action 聚合计数
	var actionCounts []struct {
		Action string
		Cnt    int64
	}
	if err := s.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Select("action, count(*) as cnt").
		Where("created_at >= ?", since).
		Group("action").Scan(&actionCounts).Error; err != nil {
		return nil, err
	}
	cnt := map[string]int64{}
	for _, a := range actionCounts {
		cnt[a.Action] = a.Cnt
	}

	confirmed := cnt["task.confirm"]
	manualRB := cnt["task.manual_rollback"]
	autoRB := cnt["task.auto_rollback"]
	failed := cnt["task.apply_failed"] + cnt["task.reject"]
	expert := cnt["iptables.exec"]
	submit := cnt["task.submit"]
	drift := cnt["node.drift"]
	heal := cnt["node.heartbeat"]

	stats.Summary["submit"] = int(submit)
	stats.Summary["confirmed"] = int(confirmed)
	stats.Summary["manual_rollback"] = int(manualRB)
	stats.Summary["auto_rollback"] = int(autoRB)
	stats.Summary["failed"] = int(failed)
	stats.Summary["expert_bypass"] = int(expert)
	stats.Summary["total"] = int(submit) + int(expert)
	stats.Summary["drift_count"] = int(drift)
	stats.Summary["self_heal"] = int(heal)

	// 健康率 = 确认生效 / (确认 + 回滚 + 失败)
	effective := confirmed + manualRB + autoRB + failed
	if effective > 0 {
		stats.HealthRate = float64(confirmed) / float64(effective)
	}
	// 回滚消耗 = 回滚 / 提交
	if submit > 0 {
		stats.RollbackCost = float64(manualRB+autoRB) / float64(submit)
	}

	// distribution:保护期变更终态分布(排除专家绕过)
	stats.Distribution["success"] = int(confirmed)
	stats.Distribution["rolled_back"] = int(manualRB + autoRB)
	stats.Distribution["failed"] = int(failed)
	pending := int(submit) - int(confirmed) - int(manualRB+autoRB) - int(failed)
	if pending < 0 {
		pending = 0
	}
	stats.Distribution["pending"] = pending

	// daily:按天 + action 聚合
	var dailyCounts []struct {
		Date   string
		Action string
		Cnt    int64
	}
	if err := s.DB.WithContext(ctx).Model(&model.AuditLog{}).
		Select("date(created_at) as date, action, count(*) as cnt").
		Where("created_at >= ?", since).
		Group("date, action").Scan(&dailyCounts).Error; err != nil {
		return nil, err
	}
	dailyMap := map[string]*DailyStat{}
	for _, d := range dailyCounts {
		ds, ok := dailyMap[d.Date]
		if !ok {
			ds = &DailyStat{Date: d.Date}
			dailyMap[d.Date] = ds
		}
		switch d.Action {
		case "task.submit":
			ds.Submit = int(d.Cnt)
		case "task.confirm":
			ds.Confirm = int(d.Cnt)
		case "task.manual_rollback", "task.auto_rollback":
			ds.Rollback += int(d.Cnt)
		case "iptables.exec":
			ds.Expert = int(d.Cnt)
		case "node.drift":
			ds.Drift = int(d.Cnt)
		}
	}
	dates := make([]string, 0, len(dailyMap))
	for d := range dailyMap {
		dates = append(dates, d)
	}
	sort.Strings(dates)
	for _, d := range dates {
		stats.Daily = append(stats.Daily, *dailyMap[d])
	}
	return stats, nil
}

// ConfidenceStats 变更置信度:按 actor/node/policy 维度统计提交回滚率。
type ConfidenceStats struct {
	ByActor  map[string]*ConfidenceItem `json:"by_actor"`
	ByNode   map[string]*ConfidenceItem `json:"by_node"`
	ByPolicy map[string]*ConfidenceItem `json:"by_policy"`  // key = "policy_<id>"
}

// ConfidenceItem 单维度置信度。
type ConfidenceItem struct {
	Total      int     `json:"total"`
	RolledBack int     `json:"rolled_back"`
	Confidence float64 `json:"confidence"`
}

// Confidence 计算近 days 天变更置信度:按 actor/node/policy 维度统计提交与回滚。
func (s *Sink) Confidence(ctx context.Context, days int) (*ConfidenceStats, error) {
	if s == nil || s.DB == nil {
		return &ConfidenceStats{ByActor: map[string]*ConfidenceItem{}, ByNode: map[string]*ConfidenceItem{}, ByPolicy: map[string]*ConfidenceItem{}}, nil
	}
	if days <= 0 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days)
	var logs []model.AuditLog
	if err := s.DB.WithContext(ctx).Where("created_at >= ?", since).Find(&logs).Error; err != nil {
		return nil, err
	}

	// 收集 submit 的 taskID -> policyID 映射
	submitPolicy := map[string]uint{}
	for _, log := range logs {
		if log.Action == "task.submit" {
			var d struct {
				PolicyID uint `json:"policy_id"`
			}
			if err := json.Unmarshal([]byte(log.Detail), &d); err == nil && d.PolicyID > 0 {
				submitPolicy[log.TaskID] = d.PolicyID
			}
		}
	}

	stats := &ConfidenceStats{
		ByActor:  map[string]*ConfidenceItem{},
		ByNode:   map[string]*ConfidenceItem{},
		ByPolicy: map[string]*ConfidenceItem{},
	}

	inc := func(m map[string]*ConfidenceItem, key string, rollback bool) {
		item, ok := m[key]
		if !ok {
			item = &ConfidenceItem{}
			m[key] = item
		}
		item.Total++
		if rollback {
			item.RolledBack++
		}
	}

	for _, log := range logs {
		switch log.Action {
		case "task.submit":
			inc(stats.ByActor, log.Actor, false)
			inc(stats.ByNode, log.NodeID, false)
			if pid, ok := submitPolicy[log.TaskID]; ok {
				inc(stats.ByPolicy, fmt.Sprintf("policy_%d", pid), false)
			}
		case "task.auto_rollback", "task.manual_rollback":
			inc(stats.ByActor, log.Actor, true)
			inc(stats.ByNode, log.NodeID, true)
			if pid, ok := submitPolicy[log.TaskID]; ok {
				inc(stats.ByPolicy, fmt.Sprintf("policy_%d", pid), true)
			}
		}
	}

	// 计算置信度
	for _, v := range stats.ByActor {
		if v.Total > 0 {
			v.Confidence = float64(v.Total-v.RolledBack) / float64(v.Total)
		}
	}
	for _, v := range stats.ByNode {
		if v.Total > 0 {
			v.Confidence = float64(v.Total-v.RolledBack) / float64(v.Total)
		}
	}
	for _, v := range stats.ByPolicy {
		if v.Total > 0 {
			v.Confidence = float64(v.Total-v.RolledBack) / float64(v.Total)
		}
	}
	return stats, nil
}