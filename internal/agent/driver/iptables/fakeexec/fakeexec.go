// Package fakeexec provides an in-memory Exec implementation for iptables
// driver tests. It models the subset of iptables commands the driver uses:
// -N / -X / -F / -I / -A / -D / -C / -S. It's not a full iptables emulator —
// it's a minimal state machine that lets us assert what the driver DOES.
package fakeexec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Fake is a minimal iptables state machine. Not thread-safe outside its own
// methods; use a single Fake per test.
type Fake struct {
	mu     sync.Mutex
	Tables map[string]map[string][]string // table -> chain -> rules (each rule is the -A args without -A/chain)
	// Log records every args-list Run has been called with, in order, so tests
	// can assert on driver behavior (idempotency, flush-before-fill, etc).
	Log [][]string
}

func New() *Fake {
	return &Fake{Tables: map[string]map[string][]string{}}
}

// Run parses a small subset of iptables invocations. Everything else returns
// an error like "unsupported args in fake" so tests fail loudly if the driver
// ever calls something we haven't taught the fake yet.
func (f *Fake) Run(ctx context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Copy args into the log for later assertions.
	cp := make([]string, len(args))
	copy(cp, args)
	f.Log = append(f.Log, cp)

	table, rest, err := popTable(args)
	if err != nil {
		return "", err
	}
	f.ensureTable(table)

	if len(rest) < 2 {
		return "", fmt.Errorf("fakeexec: not enough args after -t %s: %v", table, rest)
	}

	verb := rest[0]
	switch verb {
	case "-N": // create chain
		chain := rest[1]
		if _, ok := f.Tables[table][chain]; ok {
			return "", errors.New("iptables: Chain already exists")
		}
		f.Tables[table][chain] = nil
		return "", nil

	case "-X": // delete chain
		chain := rest[1]
		delete(f.Tables[table], chain)
		return "", nil

	case "-F": // flush chain
		chain := rest[1]
		if _, ok := f.Tables[table][chain]; !ok {
			return "", errors.New("iptables: No chain/target/match by that name")
		}
		f.Tables[table][chain] = nil
		return "", nil

	case "-I": // insert at position (we only support position 1)
		chain := rest[1]
		var body []string
		if len(rest) >= 3 && rest[2] == "1" {
			body = rest[3:]
		} else {
			body = rest[2:]
		}
		f.ensureChain(table, chain)
		f.Tables[table][chain] = append([]string{joinArgs(body)}, f.Tables[table][chain]...)
		return "", nil

	case "-A": // append
		chain := rest[1]
		body := rest[2:]
		f.ensureChain(table, chain)
		f.Tables[table][chain] = append(f.Tables[table][chain], joinArgs(body))
		return "", nil

	case "-D": // delete matching rule
		chain := rest[1]
		body := rest[2:]
		target := joinArgs(body)
		rules := f.Tables[table][chain]
		for i, r := range rules {
			if r == target {
				f.Tables[table][chain] = append(rules[:i], rules[i+1:]...)
				return "", nil
			}
		}
		return "", errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")

	case "-C": // check
		chain := rest[1]
		body := rest[2:]
		target := joinArgs(body)
		for _, r := range f.Tables[table][chain] {
			if r == target {
				return "", nil
			}
		}
		return "", errors.New("iptables: Bad rule (does a matching rule exist in that chain?)")

	case "-S": // list rules for a chain
		chain := rest[1]
		if _, ok := f.Tables[table][chain]; !ok {
			return "", errors.New("iptables: No chain/target/match by that name")
		}
		var b strings.Builder
		fmt.Fprintf(&b, "-N %s\n", chain)
		for _, r := range f.Tables[table][chain] {
			fmt.Fprintf(&b, "-A %s %s\n", chain, r)
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("fakeexec: unsupported verb %q", verb)
}

func (f *Fake) ensureTable(t string) {
	if _, ok := f.Tables[t]; !ok {
		f.Tables[t] = map[string][]string{}
	}
}

func (f *Fake) ensureChain(t, c string) {
	f.ensureTable(t)
	if _, ok := f.Tables[t][c]; !ok {
		f.Tables[t][c] = nil
	}
}

// popTable pulls the leading "-t <table>" pair off args and returns the rest.
func popTable(args []string) (string, []string, error) {
	if len(args) < 2 || args[0] != "-t" {
		return "", nil, fmt.Errorf("fakeexec: expected leading -t <table>, got %v", args)
	}
	return args[1], args[2:], nil
}

func joinArgs(a []string) string { return strings.Join(a, " ") }

// Snapshot returns a deterministic textual dump of every chain, used by tests
// that want to compare full state.
func (f *Fake) Snapshot() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tables []string
	for t := range f.Tables {
		tables = append(tables, t)
	}
	// sort for stability
	sortStrings(tables)
	var b strings.Builder
	for _, t := range tables {
		var chains []string
		for c := range f.Tables[t] {
			chains = append(chains, c)
		}
		sortStrings(chains)
		for _, c := range chains {
			fmt.Fprintf(&b, "%s/%s:\n", t, c)
			for _, r := range f.Tables[t][c] {
				fmt.Fprintf(&b, "  %s\n", r)
			}
		}
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
