// Package pocs holds the four proof-of-concept crashers the fuzz harness found
// in go-zenon release/0.0.9, as data so the CLI (cmd poc) drives the triggers
// against the real node functions.
package pocs

import (
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/vm/abi"
)

// PoC is one proof of concept. Build returns a human description of the crafted
// input (and stores the bytes it will feed); Trigger calls the real node code
// and is expected to panic.
//
// Reach is the triage axis that matters: "remote" means a third party (a peer,
// an RPC client, or any wallet) can drive the input to the crash across a
// trust boundary — those are the critical ones. "local" means the input only
// exists through on-disk corruption or an operator with data-dir access, which
// is a robustness defect, not an attack. Severity follows from Reach.
type PoC struct {
	ID       int
	Title    string
	Class    string
	Severity string
	Reach    string // "remote" | "local"
	Impact   string

	input []byte
	build  func(p *PoC) string
	fire   func(p *PoC)
}

// Describe builds the input and returns a one-line description of it.
func (p *PoC) Describe() string { return p.build(p) }

// Trigger calls into the node; it panics when the bug is present. It builds
// the input first (idempotent) so it is correct regardless of whether Describe
// was called, and in any call order.
func (p *PoC) Trigger() {
	if p.build != nil {
		p.build(p)
	}
	p.fire(p)
}

// All returns the four PoCs in id order.
func All() []*PoC {
	return []*PoC{
		{
			ID:       1,
			Title:    "nom.DeserializeAccountBlock — nil-pointer panic on a malformed ledger record",
			Class:    "NULL-pointer dereference in a serialization parser (defeats the caller's error handling)",
			Severity: "LOW (local only)",
			Reach:    "local",
			Impact: "NOT remotely reachable: types.Hash is a fixed [32]byte, so every block that " +
				"arrives over the wire (RLP) or RPC (JSON) is forced through fixed-size struct " +
				"fields and RE-SERIALIZED before storage, which always emits a canonical 32-byte " +
				"hash. This protobuf decoder sits on the storage-READ side of that boundary, so " +
				"the malformed field only exists through local DB corruption (truncated write after " +
				"power loss, bit-rot, data-dir tampering). Impact: a node with an already-damaged " +
				"ledger panics on read and crash-loops on restart instead of reporting corruption. " +
				"Becomes CRITICAL only if a future feature ships raw serialized blocks peer-to-peer " +
				"(state-snapshot / fast-sync) and writes them before the re-serialization step.",
			build: func(p *PoC) string {
				pb := &nom.AccountBlockProto{Version: 1, BlockType: nom.BlockTypeUserSend, Height: 2} // hash field absent
				p.input, _ = proto.Marshal(pb)
				return fmt.Sprintf("%d-byte protobuf AccountBlock with the hash field absent: % x", len(p.input), p.input)
			},
			fire: func(p *PoC) { _, _ = nom.DeserializeAccountBlock(p.input) },
		},
		{
			ID:       2,
			Title:    "nom.DeserializeMomentum — panic on a wrong-length hash field",
			Class:    "missing length validation in a serialization parser (panics instead of returning an error)",
			Severity: "LOW (local only)",
			Reach:    "local",
			Impact: "NOT remotely reachable, for the same reason as PoC #1: the storage read path only " +
				"sees protobuf that the node itself re-serialized from fixed-size structs. A " +
				"wrong-length momentum record requires local DB corruption. Availability impact: " +
				"the momentum store wedges node startup. Same future-snapshot-sync caveat applies.",
			build: func(p *PoC) string {
				pb := &nom.MomentumProto{Version: 1, Height: 42, PreviousHash: &types.HashProto{Hash: []byte{1, 2, 3, 4, 5}}}
				p.input, _ = proto.Marshal(pb)
				return fmt.Sprintf("%d-byte protobuf Momentum whose previousHash is 5 bytes: % x", len(p.input), p.input)
			},
			fire: func(p *PoC) { _, _ = nom.DeserializeMomentum(p.input) },
		},
		{
			ID:       3,
			Title:    "db.NewPatchFromDump — slice-bounds panic from an unchecked length (integer truncation)",
			Class:    "integer overflow/truncation in a length field -> out-of-bounds slice",
			Severity: "LOW (local only)",
			Reach:    "local",
			Impact: "NOT remotely reachable: these batch dumps are produced locally by the node's own " +
				"VM and read back from local leveldb (getPatch/getRollback, account_pool). A malformed " +
				"dump requires local DB corruption. Impact: the node panics on the commit/reorg/restart " +
				"read path; a damaged changes-DB is unrecoverable in place. The bug itself is a real " +
				"uint64->int truncation in vendored goleveldb and would be CRITICAL if patch bytes ever " +
				"crossed a trust boundary (snapshot sync).",
			build: func(p *PoC) string {
				// Minimized reproducer: keyType=val then a 10-byte Uvarint key
				// length whose int() conversion is a large negative number, so
				// goleveldb's `o+int(x) > len(data)` guard passes and a negative
				// length drives the read offset negative -> data[o:] panics.
				p.input = []byte{0x01, 0xd4, 0xc7, 0xd4, 0xd4, 0xd4, 0xff, 0xff, 0xfe, 0xed, 0x01}
				return fmt.Sprintf("%d-byte leveldb batch dump: % x", len(p.input), p.input)
			},
			fire: func(p *PoC) { _, _ = db.NewPatchFromDump(p.input) },
		},
		{
			ID:       4,
			Title:    `abi.NewType("") — index-out-of-range on an unmatched type string`,
			Class:    "unchecked slice index on a regexp result",
			Severity: "LOW (not node-reachable)",
			Reach:    "local",
			Impact: "Lower severity: the node's embedded contract ABIs are fixed compiled-in strings, so " +
				"consensus/network input does not reach this. It bites any tool, SDK, or future feature " +
				"that builds an ABIContract from untrusted JSON (Argument.UnmarshalJSON -> NewType): a " +
				"crafted ABI crashes the parser instead of returning the error its signature promises.",
			build: func(p *PoC) string {
				return `the empty type string "" (also produced internally by parsing the type "[]")`
			},
			fire: func(p *PoC) { _, _ = abi.NewType("") },
		},
	}
}
