package fakeexec

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Table struct {
	Chains map[string]*Chain
}

type Chain struct {
	Family   string
	Table    string
	Name     string
	Hook     string
	Priority int
	Rules    []string
}

type Fake struct {
	mu     sync.Mutex
	Tables map[string]*Table // family -> table -> chains
	Log    [][]string
}

func New() *Fake {
	return &Fake{Tables: map[string]*Table{}}
}

func (f *Fake) Run(ctx context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	cp := make([]string, len(args))
	copy(cp, args)
	f.Log = append(f.Log, cp)

	if len(args) < 2 {
		return "", fmt.Errorf("fakeexec: not enough args: %v", args)
	}

	cmd := args[0]
	switch cmd {
	case "add":
		return f.handleAdd(args[1:])
	case "delete":
		return f.handleDelete(args[1:])
	case "flush":
		return f.handleFlush(args[1:])
	case "list":
		return f.handleList(args[1:])
	}
	return "", fmt.Errorf("fakeexec: unsupported cmd %q", cmd)
}

func (f *Fake) handleAdd(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("fakeexec: add needs more args: %v", args)
	}
	switch args[0] {
	case "table":
		if len(args) < 3 {
			return "", fmt.Errorf("fakeexec: add table needs family and name: %v", args)
		}
		family := args[1]
		if f.Tables[family] == nil {
			f.Tables[family] = &Table{Chains: map[string]*Chain{}}
		}
		return "", nil
	case "chain":
		if len(args) < 5 {
			return "", fmt.Errorf("fakeexec: add chain needs family table chain hook priority: %v", args)
		}
		family, table, chain := args[1], args[2], args[3]
		if f.Tables[family] == nil {
			f.Tables[family] = &Table{Chains: map[string]*Chain{}}
		}
		if f.Tables[family].Chains[chain] != nil {
			return "", errors.New("File exists")
		}
		f.Tables[family].Chains[chain] = &Chain{
			Family: family,
			Table:  table,
			Name:   chain,
			Rules:  nil,
		}
		return "", nil
	case "rule":
		if len(args) < 5 {
			return "", fmt.Errorf("fakeexec: add rule needs family table chain exprs: %v", args)
		}
		family, chain := args[1], args[3]
		exprs := strings.Join(args[4:], " ")
		if f.Tables[family] == nil || f.Tables[family].Chains[chain] == nil {
			return "", errors.New("No such file or directory")
		}
		f.Tables[family].Chains[chain].Rules = append(f.Tables[family].Chains[chain].Rules, exprs)
		return "", nil
	}
	return "", fmt.Errorf("fakeexec: add subcommand %q not supported", args[0])
}

func (f *Fake) handleDelete(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("fakeexec: delete needs more args: %v", args)
	}
	switch args[0] {
	case "table":
		if len(args) < 3 {
			return "", fmt.Errorf("fakeexec: delete table needs family and name: %v", args)
		}
		family := args[1]
		delete(f.Tables, family)
		return "", nil
	}
	return "", fmt.Errorf("fakeexec: delete subcommand %q not supported", args[0])
}

func (f *Fake) handleFlush(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("fakeexec: flush needs family table chain: %v", args)
	}
	family, chain := args[1], args[3]
	if f.Tables[family] == nil || f.Tables[family].Chains[chain] == nil {
		return "", errors.New("No such file or directory")
	}
	f.Tables[family].Chains[chain].Rules = nil
	return "", nil
}

func (f *Fake) handleList(args []string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("fakeexec: list needs more args: %v", args)
	}
	if args[0] != "table" {
		return "", fmt.Errorf("fakeexec: list only supports table: %v", args)
	}
	family, name := args[1], args[2]
	if f.Tables[family] == nil {
		return "", errors.New("No such file or directory")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "table %s %s {\n", family, name)
	var chainNames []string
	for c := range f.Tables[family].Chains {
		chainNames = append(chainNames, c)
	}
	sort.Strings(chainNames)
	for _, c := range chainNames {
		chain := f.Tables[family].Chains[c]
		fmt.Fprintf(&b, "  chain %s {\n", c)
		fmt.Fprintf(&b, "    type filter hook %s priority 0; policy accept;\n", chain.Hook)
		for _, r := range chain.Rules {
			fmt.Fprintf(&b, "    %s\n", r)
		}
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "}\n")
	return b.String(), nil
}

func (f *Fake) Snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var families []string
	for f := range f.Tables {
		families = append(families, f)
	}
	sort.Strings(families)
	var b strings.Builder
	for _, fam := range families {
		var chains []string
		for c := range f.Tables[fam].Chains {
			chains = append(chains, c)
		}
		sort.Strings(chains)
		for _, c := range chains {
			fmt.Fprintf(&b, "%s/%s:\n", fam, c)
			for _, r := range f.Tables[fam].Chains[c].Rules {
				fmt.Fprintf(&b, "  %s\n", r)
			}
		}
	}
	return b.String()
}