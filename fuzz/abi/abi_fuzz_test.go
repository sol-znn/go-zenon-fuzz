// Package abi fuzzes the ABI codec that every embedded contract runs on the
// `Data` field of an incoming account block. When a user sends a block to the
// Pillar, Token, Stake, HTLC, Bridge, Liquidity (etc.) contract, the first
// four bytes select a method and the rest is unpacked with these routines. The
// input is entirely attacker-controlled and reaches the decoder before any
// business rule runs, so a panic or a pathological allocation here is a remote
// crash of every validator that processes the block.
package abi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zenon-network/go-zenon/vm/abi"
	"github.com/zenon-network/go-zenon/vm/embedded/definition"
)

// seedFromDir loads a structure-aware seed corpus (produced by cmd/seedgen)
// into the target. For the embedded unpacker the seeds carry real 4-byte
// method selectors, which is the dictionary trick from the fuzzing
// methodology: a coverage-guided mutator rarely guesses a 4-byte magic on its
// own, so it would otherwise stall at MethodById and never reach the argument
// decoder. Seeding the selectors walks it straight past that hard compare.
func seedFromDir(f *testing.F, name string) {
	f.Helper()
	dir := filepath.Join("..", "corpus", name)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			f.Add(data)
		}
	}
}

// contracts is the full set of embedded ABIs the node ships. Each one is a
// distinct decode surface; the fuzzer picks one per input with a selector byte
// so a single corpus exercises all of them.
var contracts = []struct {
	name string
	abi  abi.ABIContract
}{
	{"accelerator", definition.ABIAccelerator},
	{"bridge", definition.ABIBridge},
	{"common", definition.ABICommon},
	{"htlc", definition.ABIHtlc},
	{"liquidity", definition.ABILiquidity},
	{"pillars", definition.ABIPillars},
	{"plasma", definition.ABIPlasma},
	{"sentinel", definition.ABISentinel},
	{"spork", definition.ABISpork},
	{"stake", definition.ABIStake},
	{"swap", definition.ABISwap},
	{"token", definition.ABIToken},
}

// methodNames pre-computes every method name for every contract so the harness
// can call the public UnpackMethod path (which matches on name) rather than
// only the internal argument unpacker.
var methodNames = func() [][]string {
	out := make([][]string, len(contracts))
	for i, c := range contracts {
		for _, m := range c.abi.Methods {
			out[i] = append(out[i], m.Name)
		}
	}
	return out
}()

// FuzzEmbeddedUnpack feeds arbitrary input to the real contract decode path.
// Input layout matches the seed corpus: input[0] selects a contract, input[1:]
// is the block's Data field, decoded exactly as vm/embedded/implementation
// does: locate the method by its 4-byte id, then unpack the argument tail. We
// exercise both the value-producing path (UnpackValues) and the typed path
// (UnpackMethod) because they walk the type tree differently.
func FuzzEmbeddedUnpack(f *testing.F) {
	seedFromDir(f, "embedded_unpack")
	// Fallback seeds in case the corpus has not been generated yet.
	for i, c := range contracts {
		for _, m := range c.abi.Methods {
			if id := m.Id(); len(id) == 4 {
				f.Add(append([]byte{byte(i)}, append(id, make([]byte, 64)...)...))
			}
			break
		}
	}

	f.Fuzz(func(t *testing.T, input []byte) {
		if len(contracts) == 0 || len(input) == 0 {
			return
		}
		idx := int(input[0]) % len(contracts)
		data := input[1:]
		c := contracts[idx]

		// Path 1: raw method lookup + argument unpack, no name constraint.
		if method, err := c.abi.MethodById(data); err == nil {
			// data has >=4 bytes here (MethodById requires it).
			_, _ = method.Inputs.UnpackValues(data[4:])
		}

		// Path 2: the named UnpackMethod entry used by implementations.
		for _, name := range methodNames[idx] {
			var out []interface{}
			_ = c.abi.UnpackMethod(&out, name, data)
		}
	})
}

// FuzzNewType fuzzes the ABI type parser. NewType does recursive descent over
// a type string (arrays, slices, element types) and is driven from JSON ABI
// definitions; a crafted type string must fail cleanly, never panic or recurse
// without bound.
func FuzzNewType(f *testing.F) {
	// Valid-shaped seeds only. The known crashers ("" and "[]") live as
	// regression reproducers under testdata/fuzz/FuzzNewType so they are
	// replayed on every run without wedging exploration from the seed set.
	for _, s := range []string{
		"uint256", "int64", "address", "bool", "string", "bytes", "bytes32",
		"uint8[]", "address[10]", "tokenStandard", "hash", "uint256[",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		// Guard against the fuzzer burning time on megabyte type strings; the
		// real inputs are short identifiers.
		if len(s) > 256 {
			return
		}
		_, _ = abi.NewType(s)
	})
}

// FuzzABIJSON fuzzes whole-contract ABI parsing. ABIContract.UnmarshalJSON
// parses a JSON array of method/variable descriptors; it is how every embedded
// ABI above is constructed at init, and how any externally supplied ABI would
// be read.
func FuzzABIJSON(f *testing.F) {
	f.Add(`[{"type":"function","name":"x","inputs":[{"name":"a","type":"uint256"}]}]`)
	f.Add(`[{"type":"variable","name":"v","inputs":[{"name":"a","type":"bytes32"}]}]`)
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<16 {
			return
		}
		var c abi.ABIContract
		_ = c.UnmarshalJSON([]byte(strings.TrimSpace(s)))
	})
}
