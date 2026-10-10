// Package remote fuzzes the surfaces a THIRD PARTY can actually reach across a
// trust boundary — the crashes that would be remotely-triggerable denial of
// service, which is what we care about. It deliberately does NOT fuzz the
// local storage decoders (those are covered, and re-tagged LOW, in package
// decode): a stored record is always protobuf the node re-serialized from
// fixed-size structs, so attacker bytes never reach it.
//
// The real external path for an account block is:
//
//	peer TxMsg --rlp--> []*nom.AccountBlock --> chainBridge.AddAccountBlocks
//	                                        --> Supervisor.ApplyBlock(block)
//
// Crucially, ApplyBlock has NO recover (unlike ApplyMomentum, which wraps VM
// panics into ErrVmRunPanic), and no recover sits above it on the p2p handler
// goroutine. So a peer-supplied block that panics ApplyBlock crashes the whole
// node: an unauthenticated, remotely-triggerable DoS. These harnesses assert
// ApplyBlock REJECTS adversarial blocks with an error and never panics.
//
// Two targets:
//   - FuzzPeerTxRaw: arbitrary RLP bytes, exactly as a malicious peer frames a
//     TxMsg. Tests the decode + verify path for pre-auth panics.
//   - FuzzPeerTxSigned: a genuinely signed block from a genesis-funded key with
//     attacker-chosen ToAddress/Amount/Data, so execution reaches embedded
//     contract code — the depth any wallet (e.g. Syrius) can drive.
//
// A panic escaping ApplyBlock here is a CRITICAL finding. Run -parallel=1: the
// shared chain/consensus and process-global clock are not worker-safe.
package remote

import (
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/zenon-network/go-zenon/chain"
	"github.com/zenon-network/go-zenon/chain/genesis"
	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/db"
	"github.com/zenon-network/go-zenon/common/types"
	"github.com/zenon-network/go-zenon/consensus"
	"github.com/zenon-network/go-zenon/vm"

	g "github.com/zenon-network/go-zenon/chain/genesis/mock"
)

// slowCallBudget (the hang watchdog) is defined per build in budget_norace_test.go
// and budget_race_test.go: 2s normally, wider under -race, where instrumentation
// multiplies every call's wall time and a fixed 2s trips on overhead rather than
// on a real stall.

var (
	envOnce sync.Once
	sup     *vm.Supervisor
)

// env builds a genesis-only node core (chain + consensus + supervisor), the
// same construction the mock and the real node use, once. ApplyBlock reads the
// frontier and executes without committing, so one env serves every input.
func env(tb testing.TB) *vm.Supervisor {
	envOnce.Do(func() {
		// A self-managed temp dir (not tb.TempDir): the chain keeps the
		// LevelDB open for the whole process, and Go's TempDir auto-cleanup
		// would fail on Windows trying to remove still-open files, turning
		// every run falsely red. We intentionally leak this dir.
		dir, err := os.MkdirTemp("", "zenon-remote-fuzz-")
		if err != nil {
			tb.Fatalf("tempdir: %v", err)
		}
		ch := chain.NewChain(db.NewLevelDBManager(dir), genesis.NewGenesis(g.EmbeddedGenesis))
		if err := ch.Init(); err != nil {
			tb.Fatalf("chain init: %v", err)
		}
		cs := consensus.NewConsensus(db.NewMemDB(), ch, true)
		if err := cs.Init(); err != nil {
			tb.Fatalf("consensus init: %v", err)
		}
		if err := cs.Start(); err != nil {
			tb.Fatalf("consensus start: %v", err)
		}
		sup = vm.NewSupervisor(ch, cs)
	})
	return sup
}

// applyAsPeer replays the unprotected peer path: ApplyBlock with no recover of
// its own. We recover here only to tell a CLEAN rejection (error return, fine)
// apart from a PANIC (the node would have crashed — a finding), and re-raise
// the panic so `go test` records the crasher.
// guard runs fn (a call into the node on attacker-supplied input) under a
// watchdog. It distinguishes the three outcomes that matter: a clean return
// (safe), a panic (the node would have crashed — a crash finding), and a call
// that does not return within budget (a hang / algorithmic-complexity DoS — a
// finding in its own right). The goroutine is allowed to leak on a hang: we
// fail the input and the process exits.
func guard(t *testing.T, what string, fn func()) {
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		fn()
	}()
	select {
	case r := <-done:
		if r != nil {
			t.Fatalf("%s PANICKED on attacker input (remote DoS): %v", what, r)
		}
	case <-time.After(slowCallBudget):
		t.Fatalf("%s did not return within %s on attacker input (remote hang / complexity DoS)", what, slowCallBudget)
	}
}

func applyAsPeer(t *testing.T, s *vm.Supervisor, block *nom.AccountBlock) {
	guard(t, "ApplyBlock", func() { _, _ = s.ApplyBlock(block) })
}

// FuzzPeerTxRaw feeds arbitrary bytes through the exact wire decode a TxMsg
// uses, then into ApplyBlock — a malicious peer with no credentials.
func FuzzPeerTxRaw(f *testing.F) {
	for _, s := range []string{"accountblock_rlp"} {
		seedFromDir(f, s)
	}
	f.Add([]byte{0xc0}) // empty RLP list
	s := env(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		var block nom.AccountBlock
		if err := rlp.DecodeBytes(data, &block); err != nil {
			return // did not even decode as a TxMsg element
		}
		applyAsPeer(t, s, &block)
	})
}

// FuzzPeerTxSigned builds a VALID, signed send from a genesis-funded account
// (what any wallet can do) with attacker-controlled destination, amount, token
// and call data, then runs it through the peer apply path so embedded-contract
// execution is reached. This is the surface where a wallet-triggerable
// contract panic would live.
func FuzzPeerTxSigned(f *testing.F) {
	f.Add(byte(0), uint64(100), []byte{})                                    // plain-ish send
	f.Add(byte(0), uint64(0), []byte{0x3f, 0xa9, 0x37, 0x01, 0x01, 0x02})    // contract call-ish data
	s := env(f)

	// Destinations a send can target: embedded contracts (whose code then
	// runs) plus a plain user.
	targets := []types.Address{
		types.TokenContract, types.StakeContract, types.PillarContract,
		types.PlasmaContract, types.SentinelContract, types.SwapContract,
		types.LiquidityContract, types.AcceleratorContract, types.HtlcContract,
		types.BridgeContract, types.SporkContract, g.User2.Address,
	}
	tokens := []types.ZenonTokenStandard{types.ZnnTokenStandard, types.QsrTokenStandard}

	f.Fuzz(func(t *testing.T, sel byte, amount uint64, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		to := targets[int(sel)%len(targets)]
		tok := tokens[int(sel/16)%len(tokens)]

		// A send template signed by User1. GenerateFromTemplate fills hash,
		// plasma and signature and runs applyBlock — the same executor
		// ApplyBlock uses — so a panic in contract code surfaces here.
		template := &nom.AccountBlock{
			BlockType:     nom.BlockTypeUserSend,
			Address:       g.User1.Address,
			ToAddress:     to,
			Amount:        new(big.Int).SetUint64(amount),
			TokenStandard: tok,
			Data:          data,
		}
		guard(t, "signed send executor", func() { _, _ = s.GenerateFromTemplate(template, g.User1.Signer) })
	})
}
