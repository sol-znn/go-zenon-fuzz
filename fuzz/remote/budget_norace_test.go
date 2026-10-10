//go:build !race

package remote

import "time"

// slowCallBudget is the hang watchdog for a single call into the node on
// attacker input. A well-formed ApplyBlock / signed-send is sub-millisecond, so
// a decoded peer input that runs past this budget is an algorithmic-complexity
// DoS (a peer ties up the apply path) — a finding in its own right.
const slowCallBudget = 2 * time.Second
