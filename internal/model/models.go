package model

import "gorm.io/gorm"

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
