// Package audit is a thin persistence-layer wrapper around model.AuditLog.
// Every meaningful action in the Controller should call Write so we build the
// append-only history required by design.md § 11 / § 13.3.5.
package audit

import (
	"context"
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

func (s *Sink) Query(ctx context.Context, action, nodeID string, limit, offset int) ([]model.AuditLog, int64, error) {
	var logs []model.AuditLog
	var total int64
	q := s.DB.WithContext(ctx).Model(&model.AuditLog{})
	if action != "" {
		q = q.Where("action LIKE ?", "%"+action+"%")
	}
	if nodeID != "" {
		q = q.Where("node_id = ?", nodeID)
	}
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	if err := q.Order("created_at DESC").Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}
