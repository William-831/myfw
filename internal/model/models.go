package model

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
	}
}
