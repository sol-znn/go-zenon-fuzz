// Package decode fuzzes every entry point of go-zenon that turns
// attacker-influenced bytes into a Go value. These are the surfaces a remote
// peer, an RPC client, or a corrupted database page can reach, so a panic,
// hang, or unbounded allocation here is a denial-of-service against the node.
//
// Two transports matter:
//
//   - RLP, used on the p2p wire. protocol/handler.go decodes TxMsg,
//     BlocksMsg and NewBlockMsg straight into nom types with no schema
//     beyond the struct layout, so these harnesses mirror the wire exactly.
//   - protobuf, used for ledger storage and for the consensus point/election
//     stores. DeProtoAccountBlock and friends copy length-checked fields with
//     helpers that panic on a wrong length, and protobuf `bytes` fields carry
//     any length, so the fuzzer can drive the panic.
//
// A harness that only decodes is not enough: a decoder that accepts bytes but
// does not reproduce them on re-encode is a consensus hazard (two encodings of
// one block => two hashes). Where a round trip is defined, the harness asserts
// decode->encode->decode stability rather than only "did not crash".
package decode

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
)

// ---------------------------------------------------------------------------
// protobuf storage path
// ---------------------------------------------------------------------------

// FuzzAccountBlockProto drives nom.DeserializeAccountBlock, the protobuf path
// used to read account blocks back from the ledger store. DeProtoAccountBlock
// forwards the decoded `bytes` fields to types.DeProtoHash /
// types.DeProtoAddress / types.BytesToZTSPanic, each of which panics on a
// length that is not exactly the field size. Because protobuf places no length
// constraint on a `bytes` field, a crafted record panics the reader.
func FuzzAccountBlockProto(f *testing.F) {
	seedFromDir(f, "accountblock_proto")
	f.Fuzz(func(t *testing.T, data []byte) {
		ab, err := nom.DeserializeAccountBlock(data)
		if err != nil {
			return
		}
		// Decoded cleanly: re-serializing must not fail, and must round-trip.
		out, err := ab.Serialize()
		if err != nil {
			t.Fatalf("re-serialize of a decoded block failed: %v", err)
		}
		again, err := nom.DeserializeAccountBlock(out)
		if err != nil {
			t.Fatalf("re-decode of a re-serialized block failed: %v", err)
		}
		if out2, _ := again.Serialize(); !bytes.Equal(out, out2) {
			t.Fatalf("account block is not canonical under protobuf round trip")
		}
	})
}

// FuzzMomentumProto drives nom.DeserializeMomentum, the matching path for
// momentums. DeProtoMomentum also calls EnsureCache, which derives the
// producer address from the public key, so this exercises a little more than
// pure field copying.
func FuzzMomentumProto(f *testing.F) {
	seedFromDir(f, "momentum_proto")
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := nom.DeserializeMomentum(data)
		if err != nil {
			return
		}
		out, err := m.Serialize()
		if err != nil {
			t.Fatalf("re-serialize of a decoded momentum failed: %v", err)
		}
		if _, err := nom.DeserializeMomentum(out); err != nil {
			t.Fatalf("re-decode of a re-serialized momentum failed: %v", err)
		}
	})
}

// FuzzAccountHeaderProto and FuzzHashHeightProto cover the two small protobuf
// identifiers that travel inside momentum content and the downloader.
func FuzzAccountHeaderProto(f *testing.F) {
	seedFromDir(f, "accountheader_proto")
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = types.DeserializeAccountHeader(data)
	})
}

func FuzzHashHeightProto(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = types.DeserializeHashHeight(data)
	})
}

// ---------------------------------------------------------------------------
// RLP wire path
// ---------------------------------------------------------------------------

// FuzzAccountBlockRLP mirrors the TxMsg handler: protocol/handler.go decodes a
// peer's transaction list with msg.Decode, which is rlp.Decode, into
// []*nom.AccountBlock. nom.AccountBlock carries a *big.Int, nested descendant
// blocks, and several byte slices with no length tag, so this is the surface a
// remote peer reaches with no authentication.
func FuzzAccountBlockRLP(f *testing.F) {
	seedFromDir(f, "accountblock_rlp")
	f.Fuzz(func(t *testing.T, data []byte) {
		var ab nom.AccountBlock
		if err := rlp.DecodeBytes(data, &ab); err != nil {
			return
		}
		// A value that decodes from the wire must re-encode without blowing up.
		_, _ = rlp.EncodeToBytes(&ab)
	})
}

// FuzzDetailedMomentumRLP mirrors BlocksMsg / NewBlockMsg, which decode a
// *nom.DetailedMomentum (a momentum plus its account blocks) and then call
// EnsureCache on the result. This is the heaviest wire structure.
func FuzzDetailedMomentumRLP(f *testing.F) {
	seedFromDir(f, "detailedmomentum_rlp")
	f.Fuzz(func(t *testing.T, data []byte) {
		var dm nom.DetailedMomentum
		if err := rlp.DecodeBytes(data, &dm); err != nil {
			return
		}
		// The handler unconditionally dereferences dm.Momentum after decode;
		// a nil here would be a remote nil-dereference, so flag it.
		if dm.Momentum == nil {
			t.Fatalf("DetailedMomentum decoded with nil Momentum but no error: " +
				"protocol/handler.go dereferences this on the wire")
		}
		dm.Momentum.EnsureCache()
	})
}

// FuzzHashSliceRLP mirrors BlockHashesMsg / NewBlockHashesMsg, which decode a
// []types.Hash. A types.Hash is a fixed [32]byte, so RLP has to reject wrong
// lengths; this checks it does so without a panic for any framing.
func FuzzHashSliceRLP(f *testing.F) {
	f.Add([]byte{0xc0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var hashes []types.Hash
		_ = rlp.DecodeBytes(data, &hashes)
	})
}

// ---------------------------------------------------------------------------
// leveldb patch loader
// ---------------------------------------------------------------------------

// FuzzPatchDump drives db.NewPatchFromDump, the loader for serialized leveldb
// write batches. VM changes are persisted and replayed as these dumps, so a
// loader that panics or loops on a malformed batch strands the account whose
// changes cannot be read back.
func FuzzPatchDump(f *testing.F) {
	seedFromDir(f, "patch_dump")
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = db.NewPatchFromDump(data)
	})
}
