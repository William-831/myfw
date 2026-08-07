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
	"iptables-tool/internal/controller/rulespec"
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
	out, _, setNames, usedBuiltin, err := c.compileInstances(ctx, instances)
	if err != nil {
		return nil, nil, nil, err
	}
	sets, err := c.loadAddressSets(ctx, setNames)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compiler: load address sets: %w", err)
	}
	customChains, err := c.loadCustomChains(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compiler: load custom chains: %w", err)
	}
	// 追加 MARK 白名单内置链(按需,供 driver 创建子链并挂到系统链)
	if _, ok := usedBuiltin["MARKMANGLE"]; ok {
		customChains = append(customChains, &myfwv1.CustomChainDef{Name: "MARKMANGLE", Parent: "MYFW-MANGLE", Table: "mangle"})
	}
	if _, ok := usedBuiltin["MARKACL-FWD"]; ok {
		customChains = append(customChains, &myfwv1.CustomChainDef{Name: "MARKACL-FWD", Parent: "MYFW-FORWARD", Table: "filter"})
	}
	if _, ok := usedBuiltin["MARKACL-IN"]; ok {
		customChains = append(customChains, &myfwv1.CustomChainDef{Name: "MARKACL-IN", Parent: "MYFW-INPUT", Table: "filter"})
	}
	return out, sets, customChains, nil
}

// compileInstances 编译给定实例列表的核心逻辑,被 CompileForNode(全量下发) 与
// CompileInstances(diff 预览,含禁用实例) 共用。返回:
//   - out: 编译后的 CompiledRule(MARK 白名单实例可能多条)
//   - chainToTable: 用到的 chain -> table 映射(组链取 CustomChain.Table,内置链硬编码)
//   - setNames: 引用的地址组名(供 CompileForNode 加载 AddressSet 期望态)
//   - usedBuiltin: 用到的 MARK 白名单内置链(供 CompileForNode 追加内置链定义)
//
// 组是调度单元:组不存在或未启用时其实例不参与编译;MARK 白名单拦截实例无组(group_id=0)
// 规则落平台内置链。调用方决定传哪些实例(不限定 enabled,故禁用实例也可编译生成预览)。
func (c *Compiler) compileInstances(ctx context.Context, instances []model.NodePolicyInstance) (out []*myfwv1.CompiledRule, chainToTable map[string]string, setNames map[string]struct{}, usedBuiltin map[string]struct{}, err error) {
	chainToTable = make(map[string]string)
	setNames = make(map[string]struct{})
	usedBuiltin = make(map[string]struct{})

	// 预加载实例所属策略组(GroupID -> CustomChain)。
	groupIDs := make(map[uint]struct{})
	for i := range instances {
		if instances[i].GroupID != 0 {
			groupIDs[instances[i].GroupID] = struct{}{}
		}
	}
	groupByID := make(map[uint]*model.CustomChain)
	if len(groupIDs) > 0 {
		ids := make([]uint, 0, len(groupIDs))
		for id := range groupIDs {
			ids = append(ids, id)
		}
		var groups []model.CustomChain
		if e := c.DB.WithContext(ctx).Where("id IN ? AND enabled = ?", ids, true).Find(&groups).Error; e != nil {
			return nil, nil, nil, nil, e
		}
		for i := range groups {
			groupByID[groups[i].ID] = &groups[i]
		}
	}

	out = make([]*myfwv1.CompiledRule, 0, len(instances))
	for i := range instances {
		inst := &instances[i]
		// MARK 白名单拦截:填了源地址组+端口,group_id=0 也生效(落内置链)
		isMarkACL := inst.Action == "MARK" && (inst.Source != "" || inst.SourceGroup != "") && inst.PortRange != ""
		var groupChain, groupParent string
		if inst.GroupID != 0 {
			g, ok := groupByID[inst.GroupID]
			if !ok {
				continue // 所属组不存在或未启用,实例不生效
			}
			groupChain, groupParent = g.Name, g.Parent
			chainToTable[groupChain] = g.Table
		} else if !isMarkACL {
			continue // 无组且非 MARK 白名单,不生效
		}
		crs, e := compileInstance(inst, groupChain, groupParent)
		if e != nil {
			return nil, nil, nil, nil, fmt.Errorf("compiler: instance %d: %w", inst.ID, e)
		}
		out = append(out, crs...)
		for _, r := range crs {
			if r.Chain == "MARKMANGLE" || r.Chain == "MARKACL-FWD" || r.Chain == "MARKACL-IN" {
				usedBuiltin[r.Chain] = struct{}{}
			}
		}
		// 收集实例引用的地址组名,供 CompileForNode 加载 AddressSet 期望态。
		if inst.SourceGroup != "" {
			setNames[inst.SourceGroup] = struct{}{}
		}
		if inst.DestinationGroup != "" {
			setNames[inst.DestinationGroup] = struct{}{}
		}
	}
	// MARK 白名单内置链表名(mangle 打标 / filter 放行+兜底),供 diff 预览拼接 -A/-D 命令。
	if _, ok := usedBuiltin["MARKMANGLE"]; ok {
		chainToTable["MARKMANGLE"] = "mangle"
	}
	if _, ok := usedBuiltin["MARKACL-FWD"]; ok {
		chainToTable["MARKACL-FWD"] = "filter"
	}
	if _, ok := usedBuiltin["MARKACL-IN"]; ok {
		chainToTable["MARKACL-IN"] = "filter"
	}
	return out, chainToTable, setNames, usedBuiltin, nil
}

// CompileInstances 编译给定实例列表为 CompiledRule + chain->table 映射,供 diff 预览
// (禁用实例也需编译,以生成 -D 移除命令)。不限定 enabled,调用方决定传哪些实例。
func (c *Compiler) CompileInstances(ctx context.Context, instances []model.NodePolicyInstance) ([]*myfwv1.CompiledRule, map[string]string, error) {
	rules, chainToTable, _, _, err := c.compileInstances(ctx, instances)
	return rules, chainToTable, err
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

// compileInstance 将节点策略实例编译为 CompiledRule(可多条:MARK 白名单拦截时自动追加
// 放行/兜底规则)。方向与子链从所属策略组继承(groupChain=组名,groupParent=父链名);
// MARK 白名单拦截实例无组(group_id=0),规则落平台内置链。rule id 用 "i<实例ID>"。
func compileInstance(inst *model.NodePolicyInstance, groupChain, groupParent string) ([]*myfwv1.CompiledRule, error) {
	// 编译前 rulespec 校验:确保规则可执行,防旧脏数据绕过入口校验。
	if err := (rulespec.Spec{
		Action: inst.Action, Direction: inst.Direction, Mark: inst.Mark,
		MatchMark: inst.MatchMark, NatTo: inst.NatTo, Protocol: inst.Protocol,
		PortRange: inst.PortRange, Source: inst.Source, SourceGroup: inst.SourceGroup,
	}).Validate(); err != nil {
		return nil, fmt.Errorf("instance %d: %w", inst.ID, err)
	}
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

	// MARK 白名单拦截:填了源地址组+端口,自动生成完整拦截链(对用户透明,落平台内置链):
	//   1. 打标(内置 mangle 链 MARKMANGLE):只匹配目的端口,给所有源打标--清空 source/
	//      source_group,否则非白名单不打标,兜底 DROP 匹配不到,拦截失效。DNAT 前 dport
	//      仍是宿主端口。实现"端口标识"。
	//   2. 白名单+标 -> ACCEPT(内置 filter 链,优先级 P):源地址组控制放行,实现"源IP管控"。
	//   3. 标 -> DROP 兜底(优先级 P+1,白名单先匹配,其余带标包拒绝)。
	// 流量方向决定过滤链落点:FORWARD(容器转发)->MARKACL-FWD,INPUT(主机入站)->MARKACL-IN。
	if inst.Action == "MARK" && (inst.Source != "" || inst.SourceGroup != "") && inst.PortRange != "" {
		// 打标只匹配目的端口:清空 source/source_group/destination/match_mark,
		// 否则旧数据残留(如 destination/match_mark)会让打标规则带额外条件,
		// 非白名单不打标,兜底 DROP 匹配不到,拦截失效。
		main.Source = ""
		main.SourceGroup = ""
		main.Destination = ""
		main.MatchMark = 0
		main.Chain = "MARKMANGLE"
		main.Description = inst.Description + " (白名单打标:按端口)"
		aclChain := "MARKACL-FWD"
		aclDir := myfwv1.Direction_DIRECTION_FORWARD
		if inst.Direction == "INPUT" {
			aclChain = "MARKACL-IN"
			aclDir = myfwv1.Direction_DIRECTION_INBOUND
		}
		base := "i" + strconv.FormatUint(uint64(inst.ID), 10)
		rules = append(rules,
			&myfwv1.CompiledRule{
				Id:          base + "-acl",
				Direction:   aclDir,
				Source:      inst.Source,
				SourceGroup: inst.SourceGroup,
				MatchMark:   inst.Mark,
				Action:      myfwv1.Action_ACTION_ACCEPT,
				Chain:       aclChain,
				Priority:    int32(inst.Priority),
				Description: "白名单放行: " + inst.Description,
			},
			&myfwv1.CompiledRule{
				Id:          base + "-drop",
				Direction:   aclDir,
				MatchMark:   inst.Mark,
				Action:      myfwv1.Action_ACTION_DROP,
				Chain:       aclChain,
				Priority:    int32(inst.Priority) + 1,
				Description: "白名单兜底拒绝: " + inst.Description,
			},
		)
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
