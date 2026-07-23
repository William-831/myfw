// Package driver defines the Firewall Driver abstraction used by the Agent
// to converge the local host to a Controller-issued RuleSet. Concrete
// implementations live in sub-packages (iptables, nftables, ...).
//
// The interface is intentionally small and stateless-per-call: each method
// operates on the driver's own managed namespace (MYFW-* chains / myfw table)
// and never touches rules it does not own (design.md § 7).
package driver

import (
	"context"

	myfwv1 "iptables-tool/api/myfw/v1"
)

// Driver operates the host's firewall inside the MYFW namespace on behalf of
// the Controller. All methods take a context so shutdown / timeouts propagate.
type Driver interface {
	// Backend reports which FirewallBackend this driver implements.
	Backend() myfwv1.FirewallBackend

	// Init creates the MYFW chains/table and inserts the jump rules that
	// route traffic from the system chains into MYFW. Idempotent.
	Init(ctx context.Context) error

	// Apply converges the MYFW namespace to exactly `rules`. Rules outside
	// the MYFW namespace are never touched. Returns the hash of the
	// resulting normalized state so the Controller can confirm convergence.
	Apply(ctx context.Context, rules []*myfwv1.CompiledRule) (hash string, err error)

	// Snapshot serializes the current MYFW namespace so it can later be
	// restored verbatim. Format is opaque to callers.
	Snapshot(ctx context.Context) (payload string, hash string, err error)

	// Restore returns MYFW to the state captured by a prior Snapshot.
	Restore(ctx context.Context, payload string) error

	// Hash returns a stable hash of the current MYFW namespace, computed
	// with the same normalization Apply uses.
	Hash(ctx context.Context) (string, error)

	// Teardown removes the MYFW chains/table and their jump rules. Only
	// invoked when a node is being decommissioned (design.md § 15 / § 8.4).
	Teardown(ctx context.Context) error
}
