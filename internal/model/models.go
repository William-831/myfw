package model

import (
	"encoding/json"

	"gorm.io/gorm"
)

// AllModels returns every entity in migration order. Used by AutoMigrate and
// by tests. Keep this in sync when adding new tables.
func AllModels() []any {
	return []any{
		&Node{},
		&NodeCapability{},
		&Certificate{},
		&BootstrapToken{},
		&Policy{},
		&PolicyVersion{},
		&Rule{},
		&Task{},
		&Approval{},
		&Snapshot{},
		&AuditLog{},
		&IptablesRule{},
		&AddressGroup{},
		&CustomChain{},
		&PolicyTemplate{},
		&NodePolicyInstance{},
		&User{},
	}
}

// MigratePolicyGroupID 回填存量 Policy.GroupID:按 Chain(子链名)匹配 CustomChain.Name。
// 两级模型上线时,旧策略的 Chain 字段指向的子链名用于关联对应策略组。
func MigratePolicyGroupID(db *gorm.DB) error {
	var chains []CustomChain
	if err := db.Find(&chains).Error; err != nil {
		return err
	}
	nameToID := make(map[string]uint, len(chains))
	for i := range chains {
		nameToID[chains[i].Name] = chains[i].ID
	}
	var policies []Policy
	if err := db.Where("(group_id IS NULL OR group_id = 0) AND chain <> ''").Find(&policies).Error; err != nil {
		return err
	}
	for i := range policies {
		gid, ok := nameToID[policies[i].Chain]
		if !ok {
			continue
		}
		if err := db.Model(&Policy{}).Where("id = ?", policies[i].ID).Update("group_id", gid).Error; err != nil {
			return err
		}
	}
	return nil
}

// MigratePolicyToTemplate 将存量 Policy 迁移为 PolicyTemplate + NodePolicyInstance。
// 幂等:NodePolicyInstance 表已有数据则跳过。一个 Policy -> 一个模板;targets 的每个
// 节点 -> 一个实例(全量复制规则参数)。迁移后旧 Policy 保留,编译不再读。
func MigratePolicyToTemplate(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var instCount int64
		if err := tx.Model(&NodePolicyInstance{}).Count(&instCount).Error; err != nil {
			return err
		}
		if instCount > 0 {
			return nil // 已迁移
		}
		var policies []Policy
		if err := tx.Find(&policies).Error; err != nil {
			return err
		}
		for i := range policies {
			p := &policies[i]
			tpl := PolicyTemplate{
				Name: p.Name, GroupID: p.GroupID, Source: p.Source, Destination: p.Destination,
				Protocol: p.Protocol, PortRange: p.PortRange, Action: p.Action, Mark: p.Mark,
				NatTo: p.NatTo, SourceGroup: p.SourceGroup, DestinationGroup: p.DestinationGroup,
				MatchMark: p.MatchMark, MarkACLGroupID: p.MarkACLGroupID, Priority: p.Priority,
				Description: p.Description, Enabled: p.Enabled,
			}
			if err := tx.Create(&tpl).Error; err != nil {
				return err
			}
			nodeIDs, err := resolveTargetNodeIDs(tx, p.Targets)
			if err != nil {
				return err
			}
			for _, nid := range nodeIDs {
				inst := NodePolicyInstance{
					TemplateID: tpl.ID, NodeID: nid, Name: p.Name, GroupID: p.GroupID,
					Source: p.Source, Destination: p.Destination, Protocol: p.Protocol,
					PortRange: p.PortRange, Action: p.Action, Mark: p.Mark, NatTo: p.NatTo,
					SourceGroup: p.SourceGroup, DestinationGroup: p.DestinationGroup,
					MatchMark: p.MatchMark, MarkACLGroupID: p.MarkACLGroupID, Priority: p.Priority,
					Description: p.Description, Enabled: p.Enabled,
				}
				if err := tx.Create(&inst).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// resolveTargetNodeIDs 解析 Policy.Targets JSON,返回目标节点ID列表。
// node_ids 直接用;labels 按交集匹配 nodes 表。手写解析避免循环依赖 policy 包。
func resolveTargetNodeIDs(tx *gorm.DB, targets string) ([]string, error) {
	if targets == "" {
		return nil, nil
	}
	var spec struct {
		NodeIDs []string `json:"node_ids"`
		Labels  []string `json:"labels"`
	}
	if err := json.Unmarshal([]byte(targets), &spec); err != nil {
		return nil, err
	}
	if len(spec.NodeIDs) > 0 {
		return spec.NodeIDs, nil
	}
	if len(spec.Labels) == 0 {
		return nil, nil
	}
	var nodes []Node
	if err := tx.Find(&nodes).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(nodes))
	for i := range nodes {
		if hasAllLabelsMigrate(parseLabelsMigrate(nodes[i].Labels), spec.Labels) {
			out = append(out, nodes[i].ID)
		}
	}
	return out, nil
}

func parseLabelsMigrate(s string) []string {
	if s == "" {
		return nil
	}
	var arr []string
	if err := json.Unmarshal([]byte(s), &arr); err == nil {
		return arr
	}
	return nil
}

func hasAllLabelsMigrate(have, want []string) bool {
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
