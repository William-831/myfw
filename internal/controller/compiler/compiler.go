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
	"sort"
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
// nodeID, plus the AddressSets and CustomChains referenced, derived from every
// ENABLED policy whose targets include the node. All slices are stable
// (rules by priority ASC then policy id ASC; sets/customChains by name), so
// the same input state always compiles to the same hash on the Agent side.
func (c *Compiler) CompileForNode(ctx context.Context, nodeID string) ([]*myfwv1.CompiledRule, []*myfwv1.AddressSet, []*myfwv1.CustomChainDef, error) {
	// 节点策略实例:编译只读实例(独立参数快照),模板修改不影响已存在实例。
	var instances []model.NodePolicyInstance
	err := c.DB.WithContext(ctx).
		Where("node_id = ? AND enabled = ?", nodeID, true).
		Order("priority ASC, id ASC").
		Find(&instances).Error
	if err != nil {
		return nil, nil, nil, err
	}

	// 预加载实例所属策略组(GroupID -> CustomChain)。组是调度单元:组不存在或
	// 未启用时,其实例不参与编译(父链不会 jump 到该子链)。
	groupIDs := make(map[uint]struct{})
	for i := range instances {
		groupIDs[instances[i].GroupID] = struct{}{}
		if instances[i].MarkACLGroupID != 0 {
			groupIDs[instances[i].MarkACLGroupID] = struct{}{} // MARK 联动放行组也需加载
		}
	}
	groupByID := make(map[uint]*model.CustomChain)
	if len(groupIDs) > 0 {
		ids := make([]uint, 0, len(groupIDs))
		for id := range groupIDs {
			ids = append(ids, id)
		}
		var groups []model.CustomChain
		if err := c.DB.WithContext(ctx).Where("id IN ? AND enabled = ?", ids, true).Find(&groups).Error; err != nil {
			return nil, nil, nil, err
		}
		for i := range groups {
			groupByID[groups[i].ID] = &groups[i]
		}
	}

	out := make([]*myfwv1.CompiledRule, 0, len(instances))
	setNames := make(map[string]struct{})
	for i := range instances {
		inst := &instances[i]
		g, ok := groupByID[inst.GroupID]
		if !ok {
			continue // 所属组不存在或未启用,实例不生效
		}
		var aclGroup *model.CustomChain
		if inst.MarkACLGroupID != 0 {
			aclGroup = groupByID[inst.MarkACLGroupID]
		}
		crs, err := compileInstance(inst, g.Name, g.Parent, aclGroup)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("compiler: instance %d: %w", inst.ID, err)
		}
		out = append(out, crs...)
		// 收集实例引用的地址组名,稍后一次性加载为下发的 AddressSet 期望态。
		if inst.SourceGroup != "" {
			setNames[inst.SourceGroup] = struct{}{}
		}
		if inst.DestinationGroup != "" {
			setNames[inst.DestinationGroup] = struct{}{}
		}
	}
	sets, err := c.loadAddressSets(ctx, setNames)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compiler: load address sets: %w", err)
	}
	customChains, err := c.loadCustomChains(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compiler: load custom chains: %w", err)
	}
	return out, sets, customChains, nil
}

// loadCustomChains 加载所有启用的自定义子链,转为下发的 CustomChainDef 期望态。
// 按 priority 排序:父链中 jump 到各子链的顺序由组优先级决定(值小排前)。
func (c *Compiler) loadCustomChains(ctx context.Context) ([]*myfwv1.CustomChainDef, error) {
	var chains []model.CustomChain
	if err := c.DB.WithContext(ctx).Where("enabled = ?", true).Order("priority ASC, id ASC").Find(&chains).Error; err != nil {
		return nil, err
	}
	out := make([]*myfwv1.CustomChainDef, 0, len(chains))
	for i := range chains {
		out = append(out, &myfwv1.CustomChainDef{
			Name:   chains[i].Name,
			Parent: chains[i].Parent,
			Table:  chains[i].Table,
		})
	}
	return out, nil
}

// loadAddressSets 按 name 集合加载 AddressGroup,转为下发的 AddressSet 期望态。
// 按 name 排序保证输出稳定,使同输入编译出同 hash。
func (c *Compiler) loadAddressSets(ctx context.Context, names map[string]struct{}) ([]*myfwv1.AddressSet, error) {
	if len(names) == 0 {
		return nil, nil
	}
	nameList := make([]string, 0, len(names))
	for n := range names {
		nameList = append(nameList, n)
	}
	var groups []model.AddressGroup
	if err := c.DB.WithContext(ctx).Where("name IN ?", nameList).Find(&groups).Error; err != nil {
		return nil, err
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	sets := make([]*myfwv1.AddressSet, 0, len(groups))
	for i := range groups {
		var members []string
		if groups[i].Members != "" {
			_ = json.Unmarshal([]byte(groups[i].Members), &members)
		}
		sets = append(sets, &myfwv1.AddressSet{
			Name:    groups[i].Name,
			Kind:    groups[i].Kind,
			Members: members,
		})
	}
	return sets, nil
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

// compileInstance 将节点策略实例编译为 CompiledRule(可多条:MARK 联动时自动追加放行规则)。
// 方向与子链从所属策略组继承(groupChain=组名,groupParent=父链名)。rule id 用 "i<实例ID>"。
func compileInstance(inst *model.NodePolicyInstance, groupChain, groupParent string, aclGroup *model.CustomChain) ([]*myfwv1.CompiledRule, error) {
	dir, err := parseDirection(parentToDirection(groupParent))
	if err != nil {
		return nil, err
	}
	proto, err := parseProtocol(inst.Protocol)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(inst.Action)
	if err != nil {
		return nil, err
	}

	main := &myfwv1.CompiledRule{
		Id:               "i" + strconv.FormatUint(uint64(inst.ID), 10),
		Direction:        dir,
		Source:           inst.Source,
		Destination:      inst.Destination,
		Protocol:         proto,
		PortRange:        inst.PortRange,
		Action:           act,
		Mark:             inst.Mark,
		NatTo:            inst.NatTo,
		SourceGroup:      inst.SourceGroup,
		DestinationGroup: inst.DestinationGroup,
		MatchMark:        inst.MatchMark,
		Chain:            groupChain,
		Priority:         int32(inst.Priority),
		Description:      inst.Description,
	}
	rules := []*myfwv1.CompiledRule{main}

	// MARK 联动:填了白名单+放行组,自动生成 filter 放行规则(match_mark+白名单 ACCEPT)
	if inst.Action == "MARK" && inst.SourceGroup != "" && aclGroup != nil {
		aclDir, _ := parseDirection(parentToDirection(aclGroup.Parent))
		rules = append(rules, &myfwv1.CompiledRule{
			Id:          "i" + strconv.FormatUint(uint64(inst.ID), 10) + "-acl",
			Direction:   aclDir,
			SourceGroup: inst.SourceGroup,
			MatchMark:   inst.Mark,
			Action:      myfwv1.Action_ACTION_ACCEPT,
			Chain:       aclGroup.Name,
			Priority:    int32(inst.Priority),
			Description: "MARK 联动放行: " + inst.Description,
		})
	}
	return rules, nil
}

// parentToDirection 将父链名(MYFW-INPUT 等)映射为方向字符串。nat/mangle 父链
// 无对应方向,返回空(UNSPECIFIED)--新模型下落点由 Chain(组名)决定,方向仅用于审计。
func parentToDirection(parent string) string {
	switch parent {
	case "MYFW-INPUT":
		return "INBOUND"
	case "MYFW-OUTPUT":
		return "OUTBOUND"
	case "MYFW-FORWARD":
		return "FORWARD"
	}
	return ""
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
