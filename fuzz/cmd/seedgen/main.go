// seedgen writes a seed corpus of valid, in-protocol encodings for the decode
// fuzzers. Starting the mutator from real account blocks, momentums, headers
// and leveldb patch dumps means it spends its budget on the field *contents*
// and framing around a known-good skeleton, instead of first having to
// rediscover protobuf and RLP from zero.
//
// Output layout (consumed by fuzz/decode/seed.go):
//
//	corpus/accountblock_proto/   nom.AccountBlock, protobuf
//	corpus/momentum_proto/       nom.Momentum, protobuf
//	corpus/accountheader_proto/  types.AccountHeader, protobuf
//	corpus/accountblock_rlp/     nom.AccountBlock, RLP (p2p wire)
//	corpus/detailedmomentum_rlp/ nom.DetailedMomentum, RLP (p2p wire)
//	corpus/patch_dump/           db.Patch leveldb batch dump
//
// Usage: go run ./cmd/seedgen -out ../corpus
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/vm/abi"
	"github.com/zenon-network/go-zenon/vm/embedded/definition"
)

func main() {
	out := flag.String("out", "corpus", "corpus output directory")
	flag.Parse()

	blocks := sampleAccountBlocks()
	// Add a deeply nested block: DeProtoAccountBlock / RLP decode recurse once
	// per DescendantBlock, and momentum content nests too. A malformed input
	// with thousands of levels is the recursion / stack-exhaustion class from
	// the parser-vuln playbook, so we hand the mutator a nested skeleton to
	// grow. 64 levels is cheap to encode and already pushes the decoder deep.
	blocks = append(blocks, nestedBlock(64))
	for i, b := range blocks {
		if data, err := b.Serialize(); err == nil {
			write(*out, "accountblock_proto", i, data)
		}
		if data, err := rlp.EncodeToBytes(b); err == nil {
			write(*out, "accountblock_rlp", i, data)
		}
	}

	// Structure-aware dictionary for the embedded-contract unpacker: for every
	// method of every embedded ABI, emit [contractSelector | 4-byte methodId |
	// zero-padded arg tail] at a few tail lengths. These carry the exact
	// 4-byte selectors a coverage-guided mutator cannot guess, so the fuzzer
	// starts past MethodById and inside each contract's argument decoder.
	writeEmbeddedDict(*out)

	for i, m := range sampleMomentums() {
		if data, err := m.Serialize(); err == nil {
			write(*out, "momentum_proto", i, data)
		}
		dm := &nom.DetailedMomentum{Momentum: m, AccountBlocks: blocks}
		if data, err := rlp.EncodeToBytes(dm); err == nil {
			write(*out, "detailedmomentum_rlp", i, data)
		}
	}

	for i, h := range sampleHeaders() {
		if data, err := h.Serialize(); err == nil {
			write(*out, "accountheader_proto", i, data)
		}
	}

	for i, data := range samplePatchDumps() {
		write(*out, "patch_dump", i, data)
	}

	fmt.Println("seed corpus written to", *out)
}

func sampleAccountBlocks() []*nom.AccountBlock {
	h := hashOf("from")
	return []*nom.AccountBlock{
		{
			Version:         1,
			ChainIdentifier: 1,
			BlockType:       nom.BlockTypeUserSend,
			Height:          2,
			PreviousHash:    hashOf("prev"),
			Address:         types.ParseAddressPanic("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"),
			ToAddress:       types.TokenContract,
			Amount:          big.NewInt(1000),
			TokenStandard:   types.ZnnTokenStandard,
			MomentumAcknowledged: types.HashHeight{Hash: hashOf("mom"), Height: 1},
			Data:            []byte{0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02},
			PublicKey:       randBytes(32),
			Signature:       randBytes(64),
		},
		{
			Version:         1,
			ChainIdentifier: 1,
			BlockType:       nom.BlockTypeUserReceive,
			Height:          1,
			Address:         types.ParseAddressPanic("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"),
			Amount:          big.NewInt(0),
			TokenStandard:   types.ZeroTokenStandard,
			FromBlockHash:   h,
			PublicKey:       randBytes(32),
			Signature:       randBytes(64),
		},
	}
}

// nestedBlock builds a send block carrying depth-1 nested DescendantBlocks, so
// the decoder recurses `depth` times. Used to seed the recursion oracle.
func nestedBlock(depth int) *nom.AccountBlock {
	b := &nom.AccountBlock{
		Version:       1,
		BlockType:     nom.BlockTypeUserSend,
		Address:       types.ParseAddressPanic("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"),
		ToAddress:     types.TokenContract,
		Amount:        big.NewInt(1),
		TokenStandard: types.ZnnTokenStandard,
	}
	cur := b
	for i := 0; i < depth; i++ {
		child := &nom.AccountBlock{
			Version:       1,
			BlockType:     nom.BlockTypeContractSend,
			Address:       types.TokenContract,
			ToAddress:     types.ParseAddressPanic("z1qzal6c5s9rjnnxd2z7dvdhjxpmmj4fmw56a0mz"),
			Amount:        big.NewInt(0),
			TokenStandard: types.ZnnTokenStandard,
		}
		cur.DescendantBlocks = []*nom.AccountBlock{child}
		cur = child
	}
	return b
}

var embeddedABIs = map[string]abi.ABIContract{
	"accelerator": definition.ABIAccelerator,
	"bridge":      definition.ABIBridge,
	"common":      definition.ABICommon,
	"htlc":        definition.ABIHtlc,
	"liquidity":   definition.ABILiquidity,
	"pillars":     definition.ABIPillars,
	"plasma":      definition.ABIPlasma,
	"sentinel":    definition.ABISentinel,
	"spork":       definition.ABISpork,
	"stake":       definition.ABIStake,
	"swap":        definition.ABISwap,
	"token":       definition.ABIToken,
}

// contractOrder must match the `contracts` slice order in the abi harness so
// the leading selector byte picks the same contract.
var contractOrder = []string{
	"accelerator", "bridge", "common", "htlc", "liquidity", "pillars",
	"plasma", "sentinel", "spork", "stake", "swap", "token",
}

func writeEmbeddedDict(out string) {
	n := 0
	for sel, name := range contractOrder {
		c := embeddedABIs[name]
		for _, m := range c.Methods {
			id := m.Id()
			if len(id) != 4 {
				continue
			}
			for _, tail := range []int{0, 32, 96} {
				buf := append([]byte{byte(sel)}, id...)
				buf = append(buf, make([]byte, tail)...)
				write(out, "embedded_unpack", n, buf)
				n++
			}
		}
	}
}

func sampleMomentums() []*nom.Momentum {
	return []*nom.Momentum{
		{
			Version:         1,
			ChainIdentifier: 1,
			Height:          42,
			PreviousHash:    hashOf("mprev"),
			TimestampUnix:   1600000000,
			Data:            []byte{0x01, 0x02, 0x03},
			PublicKey:       randBytes(32),
			Signature:       randBytes(64),
		},
	}
}

func sampleHeaders() []*types.AccountHeader {
	return []*types.AccountHeader{
		{
			Address:    types.PillarContract,
			HashHeight: types.HashHeight{Hash: hashOf("h"), Height: 7},
		},
	}
}

func samplePatchDumps() [][]byte {
	p := db.NewPatch()
	p.Put([]byte("balance/znn"), big.NewInt(500).Bytes())
	p.Put([]byte("balance/qsr"), big.NewInt(42).Bytes())
	p.Delete([]byte("stale"))
	return [][]byte{p.Dump()}
}

// helpers

func hashOf(s string) types.Hash {
	sum := sha256.Sum256([]byte(s))
	h, _ := types.BytesToHash(sum[:])
	return h
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func write(root, name string, i int, data []byte) {
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	path := filepath.Join(dir, fmt.Sprintf("seed_%02d", i))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		panic(err)
	}
}
