// Package chain is the stateful, semantic fuzzer. The decoder harnesses stop
// at "the bytes parsed"; this one builds a real node (genesis, chain,
// consensus, VM supervisor, pillar producers via zenon/mock) and drives a
// program of adversarial account blocks through the full pipeline:
//
//	template -> supervisor.GenerateFromTemplate -> verifier -> chain insert
//	        -> momentum production -> embedded-contract auto-receive
//
// This is where the embedded contracts (Token, Stake, Pillar, HTLC, Bridge,
// Liquidity, Swap, Accelerator, Plasma, Sentinel, Spork) actually execute on
// attacker-chosen `Data`, `Amount` and `ToAddress`. A contract that rejects a
// malformed call is correct and expected; the harness only fails on a genuine
// Go panic escaping the node, or on a broken chain invariant after an
// *accepted* block.
//
// Concurrency note: the node leans on process-global state (common.Clock,
// consensus.EpochDuration), so this target is not goroutine-safe across fuzz
// workers. Run it with -parallel=1 (the runner script does). Each input builds
// and tears down its own node.
package chain

import (
	"math/big"
	"testing"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/wallet"

	g "github.com/zenon-network/go-zenon/chain/genesis/mock"
	"github.com/zenon-network/go-zenon/zenon/mock"
)

// sentinel is what fuzzT.Fatalf panics with. The mock's Insert* helpers call
// T.Fatalf when the node rejects a block (because we always pass
// expectedError=nil). For adversarial input a rejection is the normal case, so
// we convert that abort into a recoverable sentinel and treat it as "node
// cleanly rejected", distinct from any other panic, which is a real finding.
type sentinel struct{ msg string }

// fuzzT adapts the node's test hooks (common.T = {Fatalf, TempDir}) so the
// mock can run outside `go test`'s own *T. Fatalf aborts just the current
// operation instead of the whole process.
type fuzzT struct{ dir string }

func (ft *fuzzT) Fatalf(format string, args ...interface{}) { panic(sentinel{}) }
func (ft *fuzzT) TempDir() string                           { return ft.dir }

// senders are the genesis-funded keys the program can act as.
var senders = []*wallet.KeyPair{g.User1, g.User2, g.User3, g.User4, g.User5, g.Pillar1}

// targets are the destinations a send can address: the embedded contracts
// (whose implementations then run on the call data) plus two plain users.
var targets = []types.Address{
	types.TokenContract, types.StakeContract, types.PillarContract,
	types.PlasmaContract, types.SentinelContract, types.SwapContract,
	types.LiquidityContract, types.AcceleratorContract, types.HtlcContract,
	types.BridgeContract, types.SporkContract,
	g.User2.Address, g.User3.Address,
}

var tokens = []types.ZenonTokenStandard{types.ZnnTokenStandard, types.QsrTokenStandard}

// op is one decoded instruction. A program is a sequence of ops extracted from
// the fuzz input; see decodeProgram.
type op struct {
	sender    int
	target    int
	token     int
	amount    uint64
	data      []byte
	newMomsub byte // after the send, advance this many momentums (mod a small cap)
}

// FuzzChainProgram is the stateful target. The input bytes are decoded into a
// bounded program of sends and momentum advances, each replayed against a
// fresh node. The decoding is intentionally simple and total so the mutator
// can reach every branch: no input is "invalid" at the program layer.
func FuzzChainProgram(f *testing.F) {
	// A couple of structurally valid seeds: one plain ZNN send, one Token
	// contract call. The exact bytes matter less than giving the mutator a
	// non-empty starting point.
	f.Add([]byte{0, 11, 0, 1, 0, 0, 0, 0, 0, 0, 0, 10, 0, 1})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 0xaa, 0xbb, 0xcc, 0xdd, 1})

	f.Fuzz(func(t *testing.T, data []byte) {
		prog := decodeProgram(data)
		if len(prog) == 0 {
			return
		}

		ft := &fuzzT{dir: t.TempDir()}

		// Building the node must succeed; a panic during setup is a real
		// problem and should surface, so this is deliberately not guarded.
		var z mock.MockZenon
		func() {
			defer func() {
				if r := recover(); r != nil {
					// setup should never Fatalf; re-raise anything.
					panic(r)
				}
			}()
			z = mock.NewMockZenon(ft)
		}()
		defer z.StopPanic()

		prevHeight := uint64(0)

		for i := range prog {
			o := prog[i]
			sender := senders[o.sender%len(senders)]
			to := targets[o.target%len(targets)]
			tok := tokens[o.token%len(tokens)]

			template := &nom.AccountBlock{
				Address:       sender.Address,
				ToAddress:     to,
				Amount:        new(big.Int).SetUint64(o.amount),
				TokenStandard: tok,
				Data:          o.data,
			}

			// Replay one send. A sentinel means the node rejected it; any
			// other panic is a crash inside the node and must propagate so
			// `go test` records the crasher.
			runGuarded(t, func() {
				z.InsertSendBlock(template, nil, mock.SkipVmChanges)
			})

			// Advance a few momentums so contract auto-receives execute.
			adv := int(o.newMomsub%3) + 1
			for j := 0; j < adv; j++ {
				runGuarded(t, func() { z.InsertNewMomentum() })
			}

			// Invariant: the chain's frontier momentum is always readable and
			// its height never goes backwards. A violation here means an
			// accepted program left the ledger in an inconsistent state.
			front := z.Chain().GetFrontierMomentumStore().Identifier()
			if front.Height < prevHeight {
				t.Fatalf("frontier height went backwards: %d -> %d", prevHeight, front.Height)
			}
			prevHeight = front.Height
		}
	})
}

// runGuarded runs fn, swallowing a node rejection (sentinel) and re-raising
// any other panic as a genuine finding.
func runGuarded(t *testing.T, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(sentinel); ok {
				return // node rejected the adversarial block: expected.
			}
			panic(r) // real crash inside the node.
		}
	}()
	fn()
}

// decodeProgram turns raw fuzz bytes into a bounded op list. The format is a
// deliberately trivial fixed-width record so that mutations map to meaningful
// changes (flip a target byte -> different contract) and no input is rejected
// at this layer. At most 24 ops and 512 data bytes per op keep one input from
// running for minutes.
func decodeProgram(data []byte) []op {
	const maxOps = 24
	var ops []op
	r := reader{data: data}
	for len(ops) < maxOps && r.remaining() >= 12 {
		o := op{
			sender:    int(r.u8()),
			target:    int(r.u8()),
			token:     int(r.u8()),
			newMomsub: r.u8(),
			amount:    r.u64(),
		}
		dataLen := int(r.u8())
		if dataLen > 0 {
			o.data = r.bytes(dataLen)
		}
		ops = append(ops, o)
	}
	return ops
}

// reader is a total little-endian byte reader: past the end it yields zeros,
// so decodeProgram never has to error.
type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int { return len(r.data) - r.pos }
func (r *reader) u8() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}
func (r *reader) u64() uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v |= uint64(r.u8()) << (8 * i)
	}
	return v
}
func (r *reader) bytes(n int) []byte {
	if n > 512 {
		n = 512
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = r.u8()
	}
	return out
}
