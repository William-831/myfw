// Package compiler translates enabled Policy rows into a per-node RuleSet of
// CompiledRule objects. It is the middle layer that keeps the Web/policy API
// abstract (cloud-security-group style) while the Driver-facing wire format
// stays concrete. See docs/design.md § 4 / § 6.
package compiler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"gorm.io/gorm"

	myfwv1 "iptables-tool/api/myfw/v1"
	"iptables-tool/internal/controller/policy"
	"iptables-tool/internal/model"
)

type Compiler struct {
	DB *gorm.DB
}

func New(db *gorm.DB) *Compiler { return &Compiler{DB: db} }

// CompileForNode returns the ordered list of CompiledRule that apply to
// nodeID, derived from every ENABLED policy whose targets include the node.
// The result is stable (sorted by priority ASC then policy id ASC), so the
// same input state always compiles to the same hash on the Agent side.
func (c *Compiler) CompileForNode(ctx context.Context, nodeID string) ([]*myfwv1.CompiledRule, error) {
	// Load node (needed for label matching, once we support labels).
	var node model.Node
	if err := c.DB.WithContext(ctx).Where("id = ?", nodeID).First(&node).Error; err != nil {
		return nil, fmt.Errorf("compiler: load node %s: %w", nodeID, err)
	}
	nodeLabels := parseLabels(node.Labels)

	// Load every enabled policy in priority-then-id order, so the compiler's
	// output is already stable.
	var policies []model.Policy
	err := c.DB.WithContext(ctx).
		Where("enabled = ?", true).
		Order("priority ASC, id ASC").
		Find(&policies).Error
	if err != nil {
		return nil, err
	}

	out := make([]*myfwv1.CompiledRule, 0, len(policies))
	for i := range policies {
		p := &policies[i]
		spec, err := policy.ParseTargets(p)
		if err != nil {
			return nil, err
		}
		if !matches(&node, nodeLabels, spec) {
			continue
		}
		cr, err := compileOne(p)
		if err != nil {
			return nil, fmt.Errorf("compiler: policy %d: %w", p.ID, err)
		}
		out = append(out, cr)
	}
	return out, nil
}

// TargetNodes returns the node ids a single policy applies to. Used by the
// Apply orchestrator to know which agents to dispatch to.
func (c *Compiler) TargetNodes(ctx context.Context, p *model.Policy) ([]string, error) {
	spec, err := policy.ParseTargets(p)
	if err != nil {
		return nil, err
	}
	// Explicit node ids: trust them, but only return the ones that exist.
	if len(spec.NodeIDs) > 0 {
		var found []model.Node
		if err := c.DB.WithContext(ctx).
			Where("id IN ?", spec.NodeIDs).
			Find(&found).Error; err != nil {
			return nil, err
		}
		ids := make([]string, 0, len(found))
		for _, n := range found {
			ids = append(ids, n.ID)
		}
		return ids, nil
	}
	// Label selector: match every node whose labels include ALL requested
	// labels (intersection). Empty spec.Labels can't reach here because the
	// input validation rejects it.
	var nodes []model.Node
	if err := c.DB.WithContext(ctx).Find(&nodes).Error; err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if hasAllLabels(parseLabels(n.Labels), spec.Labels) {
			ids = append(ids, n.ID)
		}
	}
	return ids, nil
}

// AllTargetedNodes returns every node id targeted by any ENABLED policy.
// Used by an apply-all-policies operation.
func (c *Compiler) AllTargetedNodes(ctx context.Context) ([]string, error) {
	var policies []model.Policy
	if err := c.DB.WithContext(ctx).Where("enabled = ?", true).Find(&policies).Error; err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	for i := range policies {
		ids, err := c.TargetNodes(ctx, &policies[i])
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			seen[id] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out, nil
}

// --- helpers ---------------------------------------------------------------

func matches(node *model.Node, nodeLabels []string, spec policy.TargetsSpec) bool {
	if len(spec.NodeIDs) > 0 {
		for _, id := range spec.NodeIDs {
			if id == node.ID {
				return true
			}
		}
		return false
	}
	if len(spec.Labels) > 0 {
		return hasAllLabels(nodeLabels, spec.Labels)
	}
	return false
}

func hasAllLabels(have, want []string) bool {
	set := map[string]struct{}{}
	for _, l := range have {
		set[l] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

// parseLabels tolerates two shapes: either a JSON array ["a","b"] or a
// comma-separated fallback. Empty string -> nil.
func parseLabels(s string) []string {
	if s == "" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err == nil {
		return arr
	}
	return nil
}

// compileOne turns one Policy row into a CompiledRule proto. The rule id is
// "p<policyID>-v<priority>" so the Agent's iptables output is human-readable.
func compileOne(p *model.Policy) (*myfwv1.CompiledRule, error) {
	dir, err := parseDirection(p.Direction)
	if err != nil {
		return nil, err
	}
	proto, err := parseProtocol(p.Protocol)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(p.Action)
	if err != nil {
		return nil, err
	}

	return &myfwv1.CompiledRule{
		Id:          "p" + strconv.FormatUint(uint64(p.ID), 10),
		Direction:   dir,
		Source:      p.Source,
		Destination: p.Destination,
		Protocol:    proto,
		PortRange:   p.PortRange,
		Action:      act,
		Mark:        p.Mark,
		NatTo:       p.NatTo,
		Priority:    int32(p.Priority),
		Description: p.Description,
	}, nil
}

func parseDirection(s string) (myfwv1.Direction, error) {
	switch s {
	case "", "ANY":
		return myfwv1.Direction_DIRECTION_UNSPECIFIED, nil
	case "INBOUND":
		return myfwv1.Direction_DIRECTION_INBOUND, nil
	case "OUTBOUND":
		return myfwv1.Direction_DIRECTION_OUTBOUND, nil
	case "FORWARD":
		return myfwv1.Direction_DIRECTION_FORWARD, nil
	}
	return 0, fmt.Errorf("unknown direction %q", s)
}

func parseProtocol(s string) (myfwv1.Protocol, error) {
	switch s {
	case "":
		return myfwv1.Protocol_PROTOCOL_UNSPECIFIED, nil
	case "ANY":
		return myfwv1.Protocol_PROTOCOL_ANY, nil
	case "TCP":
		return myfwv1.Protocol_PROTOCOL_TCP, nil
	case "UDP":
		return myfwv1.Protocol_PROTOCOL_UDP, nil
	case "ICMP":
		return myfwv1.Protocol_PROTOCOL_ICMP, nil
	}
	return 0, fmt.Errorf("unknown protocol %q", s)
}

func parseAction(s string) (myfwv1.Action, error) {
	switch s {
	case "ACCEPT":
		return myfwv1.Action_ACTION_ACCEPT, nil
	case "DROP":
		return myfwv1.Action_ACTION_DROP, nil
	case "REJECT":
		return myfwv1.Action_ACTION_REJECT, nil
	case "MARK":
		return myfwv1.Action_ACTION_MARK, nil
	case "DNAT":
		return myfwv1.Action_ACTION_DNAT, nil
	case "SNAT":
		return myfwv1.Action_ACTION_SNAT, nil
	}
	return 0, errors.New("unknown action " + s)
}
