//go:build race

package remote

import "time"

// Under the race detector every call runs several times slower, so the plain 2s
// hang budget trips on instrumentation overhead, not on a real stall — an input
// flagged that way re-runs clean without -race (observed 2026-10-09:
// FuzzPeerTxSigned/27e7491a55e37592 tripped at 2.00s under -race, passed in
// ~1.5s without it). The race build uses a budget with enough headroom that
// only a genuine hang still trips it; the race detector does not make an
// infinite loop finite, so a true stall is caught regardless.
const slowCallBudget = 30 * time.Second
