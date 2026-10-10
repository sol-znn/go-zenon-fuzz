package chain

import (
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zenon-network/go-zenon/chain/nom"
	"github.com/zenon-network/go-zenon/common/types"

	g "github.com/zenon-network/go-zenon/chain/genesis/mock"
	"github.com/zenon-network/go-zenon/zenon/mock"
)

// TestPoolConcurrentAccessRace is a DIRECTED concurrency probe for the account
// and momentum pools (chain/account_pool.go, chain/momentum_pool.go). It is run
// under the race detector (`make race`): on a live node it fans several reader
// goroutines across the Chain read API while a single writer inserts account
// blocks and produces momentums, so the detector can inspect the pools' shared
// state under genuine concurrency.
//
// The surface this targets is the lock hand-off nobody else exercises:
// momentumPool.AddMomentumTransaction releases its `changes` mutex around
// broadcastInsertMomentum, which calls into accountPool.InsertMomentum ->
// rebuild under the *account* pool's mutex, mutating ap.managers. A reader that
// takes the account pool's mutex in that window (GetFrontierAccountStore,
// GetAllUncommittedAccountBlocks, GetAccountStore) is exactly the concurrent
// access a fast RPC client and the p2p producer create against a real node.
//
// Readers never assert values (they may legitimately observe a torn-but-locked
// intermediate frontier); the test exists so `-race` reports an unsynchronized
// access. A normal `go test` run executes it briefly as a smoke check; under
// `-race` it is the pool concurrency oracle. It stays single-node: the node
// leans on a process-global clock, so the one writer keeps momentum production
// serial while the reads fan out.
func TestPoolConcurrentAccessRace(t *testing.T) {
	budget := 3 * time.Second
	if testing.Short() {
		budget = 400 * time.Millisecond
	}

	ft := &fuzzT{dir: t.TempDir()}
	z := mock.NewMockZenon(ft)
	defer z.StopPanic()

	ch := z.Chain()

	// Seed the account pool with uncommitted blocks so the first momentums give
	// rebuild real work to do. Done serially, before any reader starts.
	for i := 0; i < 4; i++ {
		runGuarded(t, func() {
			z.InsertSendBlock(&nom.AccountBlock{
				Address:       g.User1.Address,
				ToAddress:     g.User2.Address,
				Amount:        big.NewInt(1),
				TokenStandard: types.ZnnTokenStandard,
			}, nil, mock.SkipVmChanges)
		})
	}

	var stop atomic.Bool
	var wg sync.WaitGroup

	readAddrs := []types.Address{
		g.User1.Address, g.User2.Address, g.User3.Address,
		types.TokenContract, types.PlasmaContract,
	}

	// Readers: hammer the pool-backed read API. Every one of these takes a pool
	// mutex internally; the race detector watches for an access that doesn't.
	for r := 0; r < 4; r++ {
		base := readAddrs[r%len(readAddrs)]
		wg.Add(1)
		go func(addr types.Address) {
			defer wg.Done()
			for !stop.Load() {
				if ms := ch.GetFrontierMomentumStore(); ms != nil {
					_ = ms.Identifier()
				}
				if as := ch.GetFrontierAccountStore(addr); as != nil {
					id := as.Identifier()
					if inner := ch.GetAccountStore(addr, id); inner != nil {
						_ = inner.Identifier()
					}
				}
				_ = ch.GetAllUncommittedAccountBlocks()
				_ = ch.GetNewMomentumContent()
			}
		}(base)
	}

	// Writer: produce momentums (each drives the AddMomentumTransaction lock
	// hand-off and accountPool.rebuild) interleaved with fresh sends, until the
	// budget expires. Single goroutine: momentum production is not concurrency
	// safe against itself (process-global clock), which is faithful to the node,
	// where one producer advances the chain.
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(budget)
		i := 0
		for time.Now().Before(deadline) {
			runGuarded(t, func() { z.InsertNewMomentum() })
			if i%3 == 0 {
				runGuarded(t, func() {
					z.InsertSendBlock(&nom.AccountBlock{
						Address:       g.User1.Address,
						ToAddress:     g.User2.Address,
						Amount:        big.NewInt(1),
						TokenStandard: types.ZnnTokenStandard,
					}, nil, mock.SkipVmChanges)
				})
			}
			i++
		}
		stop.Store(true)
	}()

	wg.Wait()
}
