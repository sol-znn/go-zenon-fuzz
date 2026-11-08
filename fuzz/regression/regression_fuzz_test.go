// Package regression holds directed regression harnesses for remote-reachable
// crash classes that are already fixed on go-zenon dev. Every harness seeds
// the pre-fix crasher input and asserts the decode path returns an error (or
// decodes cleanly) instead of panicking.
//
// Verification model: the repo pins the node at release/0.0.9 (the submodule),
// which is the pre-fix tree, so these tests FAIL there — the pre-fix code
// panics on the seeded inputs. Point the submodule at go-zenon dev and the
// same tests pass. Run them against the pinned node with:
//
//	go test ./regression/            # pre-fix: panics, i.e. the bug reproduces
//	go test -fuzz=Fuzz... ./regression/   # extend the corpus on a fixed tree
package regression

import (
	"encoding/json"
	"testing"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/rpc/api"
	"github.com/zenon-network/go-zenon/rpc/api/embedded"
)

// FuzzDeserializeAccountBlockMalformed covers the DeProto/Deserialize panic
// class fixed by go-zenon PR #154: the protobuf ledger decoders indexed
// fields without length checks (a nil or short hash, a truncated payload)
// and panicked instead of returning an error. The inputs below are the
// crashers the sweep found on release/0.0.9 (an empty payload alone reached
// DeProtoHash). Any returned error is a pass; a panic fails the run.
func FuzzDeserializeAccountBlockMalformed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x02, 0x08, 0x01})                   // version field only, no hash
	f.Add([]byte{0x3a, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05}) // 5-byte hash field
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := nom.DeserializeAccountBlock(data); err != nil {
			return
		}
		// A clean decode must re-decode; the pre-fix tree never gets here
		// on the seeds above (it panics first).
		if _, err := nom.DeserializeAccountBlock(data); err != nil {
			t.Fatalf("re-decode of a decoded block failed: %v", err)
		}
	})
}

// FuzzDeserializeMomentumMalformed is the momentum-side twin of the same
// class: a wrong-length previousHash panicked in DeProtoHash pre-fix.
func FuzzDeserializeMomentumMalformed(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x0a, 0x02, 0x08, 0x01})
	f.Fuzz(func(t *testing.T, data []byte) {
		if _, err := nom.DeserializeMomentum(data); err != nil {
			return
		}
		if _, err := nom.DeserializeMomentum(data); err != nil {
			t.Fatalf("re-decode of a decoded momentum failed: %v", err)
		}
	})
}

// FuzzAccountBlockNullDescendantToLedger covers the RPC-side null-descendant
// class fixed by go-zenon PR #190: a block whose descendantBlocks contains
// JSON null decoded without complaint on the released node, and the first
// conversion touching it — ToLedgerBlock's Copy — dereferenced the nil
// descendant and panicked inside the RPC server. The decoder-side Check now
// refuses a null entry by index, so the shape never reaches Copy.
func FuzzAccountBlockNullDescendantToLedger(f *testing.F) {
	f.Add([]byte(`{"descendantBlocks":[null]}`))
	f.Add([]byte(`{"descendantBlocks":[null,null]}`))
	f.Add([]byte(`{"descendantBlocks":[{"height":1},null]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		block := new(api.AccountBlock)
		if err := json.Unmarshal(data, block); err != nil {
			return // rejected cleanly
		}
		// Accepted: conversion to the ledger form must not dereference a
		// nil descendant.
		if _, err := block.ToLedgerBlock(); err != nil {
			return // rejected by Check on the fixed tree
		}
	})
}

// FuzzBalanceInfoNullToken covers the client-side decode class fixed in the
// PR #190 hardening family: BalanceInfo.UnmarshalJSON dereferenced the token
// marshal without a nil check, so a balance entry with a null tokenInfo (or
// one missing its embedded token) crashed any consumer decoding hostile-node
// JSON. The nil guard now skips the conversion.
func FuzzBalanceInfoNullToken(f *testing.F) {
	f.Add([]byte(`{"tokenInfo":null,"balance":"0"}`))
	f.Add([]byte(`{"balance":"0"}`))
	f.Add([]byte(`{"tokenInfo":{},"balance":"0"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		balance := new(api.BalanceInfo)
		if err := json.Unmarshal(data, balance); err != nil {
			return
		}
		if _, err := json.Marshal(balance); err != nil {
			t.Fatalf("re-marshal of an accepted balance failed: %v", err)
		}
	})
}

// FuzzBridgeRequestUnmarshalEmpty covers the bridge embedded-contract request
// class fixed by go-zenon PR #235: WrapTokenRequest/UnwrapTokenRequest
// UnmarshalJSON dereferenced an embedded marshal pointer that json.Unmarshal
// leaves nil for an empty or null body, crashing wallet/SDK consumers. The
// marshal pointer is now initialized before decoding.
func FuzzBridgeRequestUnmarshalEmpty(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"amount":"0"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		wrap := new(embedded.WrapTokenRequest)
		if err := json.Unmarshal(data, wrap); err != nil {
			return
		}
		if _, err := json.Marshal(wrap); err != nil {
			t.Fatalf("re-marshal of an accepted wrap request failed: %v", err)
		}
		unwrap := new(embedded.UnwrapTokenRequest)
		if err := json.Unmarshal(data, unwrap); err != nil {
			return
		}
		if _, err := json.Marshal(unwrap); err != nil {
			t.Fatalf("re-marshal of an accepted unwrap request failed: %v", err)
		}
	})
}
