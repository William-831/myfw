// Package policy owns the CRUD + versioning of the abstract Policy model.
// Compilation to CompiledRule and dispatch to Agents live in sibling packages
// (compiler, task). See docs/design.md § 6.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// Service is the Policy CRUD entry point.
type Service struct {
	DB *gorm.DB
}

func New(db *gorm.DB) *Service { return &Service{DB: db} }

// TargetsSpec is the parsed shape of Policy.Targets. Exactly one of NodeIDs
// or Labels should be non-empty; both empty means "no targets" and rejects.
type TargetsSpec struct {
	NodeIDs []string `json:"node_ids,omitempty"`
	Labels  []string `json:"labels,omitempty"`
}

// PolicyInput is the fields a client may set on Create/Update.
type PolicyInput struct {
	Name        string      `json:"name"`
	Direction   string      `json:"direction"`
	Source      string      `json:"source"`
	Destination string      `json:"destination"`
	Protocol    string      `json:"protocol"`
	PortRange   string      `json:"port_range"`
	Action      string      `json:"action"`
	Mark        uint32      `json:"mark"`
	NatTo       string      `json:"nat_to"`
	Priority    int         `json:"priority"`
	Description string      `json:"description"`
	Targets     TargetsSpec `json:"targets"`
	Enabled     bool        `json:"enabled"`
}

// Create inserts a new Policy row and its initial PolicyVersion (v1). The two
// writes happen in one transaction so a crash leaves neither behind.
func (s *Service) Create(ctx context.Context, in PolicyInput, author string) (*model.Policy, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	targetsJSON, err := json.Marshal(in.Targets)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal targets: %w", err)
	}

	p := &model.Policy{
		Name:        in.Name,
		Direction:   in.Direction,
		Source:      in.Source,
		Destination: in.Destination,
		Protocol:    in.Protocol,
		PortRange:   in.PortRange,
		Action:      in.Action,
		Mark:        in.Mark,
		NatTo:       in.NatTo,
		Priority:    in.Priority,
		Description: in.Description,
		Targets:     string(targetsJSON),
		Enabled:     in.Enabled,
	}

	err = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(p).Error; err != nil {
			return err
		}
		return writeVersion(tx, p, 1, author)
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Update overwrites the Policy row and appends a new version. Returns
// ErrNotFound if id doesn't exist.
func (s *Service) Update(ctx context.Context, id uint, in PolicyInput, author string) (*model.Policy, error) {
	if err := validate(in); err != nil {
		return nil, err
	}
	targetsJSON, err := json.Marshal(in.Targets)
	if err != nil {
		return nil, fmt.Errorf("policy: marshal targets: %w", err)
	}

	var updated *model.Policy
	err = s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var p model.Policy
		if err := tx.Where("id = ?", id).First(&p).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		p.Name = in.Name
		p.Direction = in.Direction
		p.Source = in.Source
		p.Destination = in.Destination
		p.Protocol = in.Protocol
		p.PortRange = in.PortRange
		p.Action = in.Action
		p.Mark = in.Mark
		p.NatTo = in.NatTo
		p.Priority = in.Priority
		p.Description = in.Description
		p.Targets = string(targetsJSON)
		p.Enabled = in.Enabled
		p.UpdatedAt = time.Now().UTC()
		if err := tx.Save(&p).Error; err != nil {
			return err
		}
		next, err := nextVersionNumber(tx, p.ID)
		if err != nil {
			return err
		}
		if err := writeVersion(tx, &p, next, author); err != nil {
			return err
		}
		updated = &p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return updated, nil
}

// Get returns a single policy.
func (s *Service) Get(ctx context.Context, id uint) (*model.Policy, error) {
	var p model.Policy
	if err := s.DB.WithContext(ctx).Where("id = ?", id).First(&p).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &p, nil
}

// List returns all policies ordered by priority then id.
func (s *Service) List(ctx context.Context) ([]model.Policy, error) {
	var out []model.Policy
	err := s.DB.WithContext(ctx).Order("priority ASC, id ASC").Find(&out).Error
	return out, err
}

// Delete removes a policy. Its version rows are kept for audit.
func (s *Service) Delete(ctx context.Context, id uint) error {
	res := s.DB.WithContext(ctx).Where("id = ?", id).Delete(&model.Policy{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// ParseTargets decodes p.Targets into a TargetsSpec.
func ParseTargets(p *model.Policy) (TargetsSpec, error) {
	var t TargetsSpec
	if p.Targets == "" {
		return t, nil
	}
	if err := json.Unmarshal([]byte(p.Targets), &t); err != nil {
		return t, fmt.Errorf("policy: parse targets: %w", err)
	}
	return t, nil
}

// --- validation ------------------------------------------------------------

var (
	ErrNotFound = errors.New("policy: not found")

	validDirections = map[string]bool{
		"INBOUND": true, "OUTBOUND": true, "FORWARD": true, "": true,
	}
	validProtocols = map[string]bool{
		"": true, "ANY": true, "TCP": true, "UDP": true, "ICMP": true,
	}
	validActions = map[string]bool{
		"ACCEPT": true, "DROP": true, "REJECT": true, "MARK": true, "DNAT": true, "SNAT": true,
	}
)

func validate(in PolicyInput) error {
	if in.Name == "" {
		return errors.New("policy: name is required")
	}
	if !validDirections[in.Direction] {
		return fmt.Errorf("policy: bad direction %q", in.Direction)
	}
	if !validProtocols[in.Protocol] {
		return fmt.Errorf("policy: bad protocol %q", in.Protocol)
	}
	if !validActions[in.Action] {
		return fmt.Errorf("policy: bad action %q", in.Action)
	}
	if in.Action == "DNAT" || in.Action == "SNAT" {
		if in.NatTo == "" {
			return fmt.Errorf("policy: %s requires nat_to", in.Action)
		}
	}
	if in.PortRange != "" && in.Protocol == "" {
		return errors.New("policy: port_range requires a protocol")
	}
	if len(in.Targets.NodeIDs) == 0 && len(in.Targets.Labels) == 0 {
		return errors.New("policy: at least one target (node_ids or labels) is required")
	}
	return nil
}

// --- versioning helpers ----------------------------------------------------

func writeVersion(tx *gorm.DB, p *model.Policy, version int64, author string) error {
	buf, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return tx.Create(&model.PolicyVersion{
		PolicyID: p.ID,
		Version:  version,
		Snapshot: string(buf),
		Author:   author,
	}).Error
}

func nextVersionNumber(tx *gorm.DB, policyID uint) (int64, error) {
	var v model.PolicyVersion
	err := tx.Where("policy_id = ?", policyID).Order("version DESC").First(&v).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return 0, err
	}
	return v.Version + 1, nil
}
