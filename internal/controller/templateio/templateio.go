// Package templateio implements template library import/export.
//
// Export serialises Mark, CustomChain, and PolicyTemplate into a portable JSON
// bundle. Import reads a bundle back, resolving name-based references (e.g.
// group_name → CustomChain.ID) so that the same file works across environments.
package templateio

import (
	"errors"
	"fmt"
	"reflect"
	"time"

	"gorm.io/gorm"

	"iptables-tool/internal/model"
)

// Bundle is the portable representation of template library data.
type Bundle struct {
	Version      string                    `json:"version"`       // schema version, currently "1.0"
	ExportedAt   time.Time                 `json:"exported_at"`   // when the bundle was exported
	Marks        []model.Mark              `json:"marks,omitempty"`
	CustomChains []model.CustomChain       `json:"custom_chains,omitempty"`
	Templates    []TemplateExport          `json:"templates,omitempty"`
	AddressGroups []model.AddressGroup     `json:"address_groups,omitempty"`
}

// TemplateExport augments PolicyTemplate with the resolved group name.
type TemplateExport struct {
	model.PolicyTemplate
	GroupName string `json:"group_name"` // resolved from GroupID at export time
}

// ImportPolicy controls how the importer handles records that already exist.
type ImportPolicy string

const (
	ImportSkip     ImportPolicy = "skip"      // skip existing records (default)
	ImportOverwrite ImportPolicy = "overwrite" // overwrite existing records
	ImportFail     ImportPolicy = "fail"      // abort on any conflict
)

// ImportResult summarises what the import did.
type ImportResult struct {
	MarksCreated     int `json:"marks_created"`
	MarksSkipped     int `json:"marks_skipped"`
	MarksOverwritten int `json:"marks_overwritten"`

	ChainsCreated     int `json:"chains_created"`
	ChainsSkipped     int `json:"chains_skipped"`
	ChainsOverwritten int `json:"chains_overwritten"`

	TemplatesCreated     int `json:"templates_created"`
	TemplatesSkipped     int `json:"templates_skipped"`
	TemplatesOverwritten int `json:"templates_overwritten"`

	Errors []string `json:"errors,omitempty"`
}

// Export reads all marks, custom chains, and templates from the database and
// returns a portable bundle. Templates have their GroupID resolved to GroupName.
func Export(db *gorm.DB) (*Bundle, error) {
	var marks []model.Mark
	if err := db.Order("id ASC").Find(&marks).Error; err != nil {
		return nil, fmt.Errorf("templateio: read marks: %w", err)
	}

	var chains []model.CustomChain
	if err := db.Order("id ASC").Find(&chains).Error; err != nil {
		return nil, fmt.Errorf("templateio: read chains: %w", err)
	}

	// Build chain name lookup by ID.
	chainName := map[uint]string{}
	for i := range chains {
		chainName[chains[i].ID] = chains[i].Name
	}

	var tpls []model.PolicyTemplate
	if err := db.Order("id ASC").Find(&tpls).Error; err != nil {
		return nil, fmt.Errorf("templateio: read templates: %w", err)
	}
	exportTpls := make([]TemplateExport, len(tpls))
	for i := range tpls {
		exportTpls[i].PolicyTemplate = tpls[i]
		exportTpls[i].GroupName = chainName[tpls[i].GroupID]
	}

	var groups []model.AddressGroup
	if err := db.Order("id ASC").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("templateio: read address groups: %w", err)
	}

	return &Bundle{
		Version:      "1.0",
		ExportedAt:   time.Now().UTC(),
		Marks:        marks,
		CustomChains: chains,
		Templates:    exportTpls,
		AddressGroups: groups,
	}, nil
}

// Import writes a bundle into the database inside a single transaction.
// The import order is: Marks → CustomChains → Templates (dependency order).
// GroupName on templates is resolved to GroupID by looking up the chain name.
func Import(db *gorm.DB, bundle *Bundle, policy ImportPolicy) (*ImportResult, error) {
	var r ImportResult
	err := db.Transaction(func(tx *gorm.DB) error {
		r = ImportResult{} // reset inside transaction

		// 1. Marks
		for i := range bundle.Marks {
			m := bundle.Marks[i]
			action, err := importOne(tx, &m, policy, "name", m.Name)
			if err != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("mark %q: %v", m.Name, err))
				if isFailPolicy(err) {
					return err
				}
				continue
			}
			switch action {
			case actionSkipped:
				r.MarksSkipped++
			case actionOverwritten:
				r.MarksOverwritten++
			default:
				r.MarksCreated++
			}
		}

		// 2. Custom chains
		for i := range bundle.CustomChains {
			c := bundle.CustomChains[i]
			action, err := importOne(tx, &c, policy, "name", c.Name)
			if err != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("chain %q: %v", c.Name, err))
				if isFailPolicy(err) {
					return err
				}
				continue
			}
			switch action {
			case actionSkipped:
				r.ChainsSkipped++
			case actionOverwritten:
				r.ChainsOverwritten++
			default:
				r.ChainsCreated++
			}
		}

		// Build chain name→ID lookup for template resolution.
		var chains []model.CustomChain
		if err := tx.Find(&chains).Error; err != nil {
			return err
		}
		chainID := map[string]uint{}
		for i := range chains {
			chainID[chains[i].Name] = chains[i].ID
		}

		// 3. Templates
		for i := range bundle.Templates {
			te := bundle.Templates[i]

			// Resolve GroupName → GroupID.
			if te.GroupName != "" {
				id, ok := chainID[te.GroupName]
				if !ok {
					err := fmt.Errorf("group_name %q not found in custom chains", te.GroupName)
					r.Errors = append(r.Errors, fmt.Sprintf("template %q: %v", te.Name, err))
					return err // group missing is a hard error
				}
				te.GroupID = id
			}

			// Build a PolicyTemplate from the export fields.
			tpl := te.PolicyTemplate
			action, err := importOne(tx, &tpl, policy, "name", te.Name)
			if err != nil {
				r.Errors = append(r.Errors, fmt.Sprintf("template %q: %v", te.Name, err))
				if isFailPolicy(err) {
					return err
				}
				continue
			}
			switch action {
			case actionSkipped:
				r.TemplatesSkipped++
			case actionOverwritten:
				r.TemplatesOverwritten++
			default:
				r.TemplatesCreated++
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// importAction describes what importOne did.
type importAction int

const (
	actionCreated     importAction = iota
	actionSkipped
	actionOverwritten
)

// importOne handles the create-or-skip-or-overwrite logic for a single record.
// lookupField is the column used for existence checks (e.g. "name").
// lookupValue is the value to match (e.g. the record's Name).
//
// Overwrite is implemented by reading the existing record's ID, then saving the
// incoming record with that ID. This avoids the trap of calling First(record)
// on the incoming pointer (which would overwrite the caller's values).
func importOne(tx *gorm.DB, record any, policy ImportPolicy, lookupField, lookupValue string) (importAction, error) {
	var count int64
	tx.Model(record).Where(lookupField+" = ?", lookupValue).Count(&count)

	if count == 0 {
		return actionCreated, tx.Create(record).Error
	}

	switch policy {
	case ImportSkip:
		return actionSkipped, nil
	case ImportOverwrite:
		// Read the existing record's ID without overwriting the incoming record.
		var existingID uint
		tx.Model(record).Select("id").Where(lookupField+" = ?", lookupValue).Scan(&existingID)
		if existingID == 0 {
			return actionCreated, fmt.Errorf("existing record not found for overwrite")
		}
		// Set the ID on the incoming record so Save() updates rather than inserts.
		v := reflect.ValueOf(record).Elem()
		if idField := v.FieldByName("ID"); idField.IsValid() && idField.CanSet() {
			idField.SetUint(uint64(existingID))
		}
		return actionOverwritten, tx.Save(record).Error
	case ImportFail:
		return actionCreated, fmt.Errorf("conflict: %w", errConflict)
	default:
		return actionCreated, fmt.Errorf("unknown import policy %q", policy)
	}
}

var errConflict = fmt.Errorf("conflict") // wrapped by ImportFail

func isFailPolicy(err error) bool { return errors.Is(err, errConflict) }